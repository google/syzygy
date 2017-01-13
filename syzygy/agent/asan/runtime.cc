// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "syzygy/agent/asan/runtime.h"

#include <algorithm>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/file_version_info.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/rand_util.h"
#include "base/version.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "base/win/wrapped_window_proc.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/crt_interceptors.h"
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/asan/logger.h"
#include "syzygy/agent/asan/memory_interceptors.h"
#include "syzygy/agent/asan/memory_interceptors_patcher.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/system_interceptors.h"
#include "syzygy/agent/asan/windows_heap_adapter.h"
#include "syzygy/agent/asan/memory_notifiers/shadow_memory_notifier.h"
#include "syzygy/agent/asan/reporters/breakpad_reporter.h"
#include "syzygy/agent/asan/reporters/crashpad_reporter.h"
#include "syzygy/crashdata/crashdata.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

// Disable all optimizations in this file. This entirely consists of code
// that runs once at startup, or once during error handling. The latter code
// is particularly useful to keep in its highest-fidelity form to help with
// diagnosing edge cases during crash processing.
#pragma optimize("", off)
#pragma auto_inline(off)

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanLogger;
using agent::asan::StackCaptureCache;
using agent::asan::WindowsHeapAdapter;

enum CrashReporterType {
  kDefaultCrashReporterType,
  kBreakpadCrashReporterType,
  kCrashpadCrashReporterType,
};

// A custom exception code we use to indicate that the exception originated
// from Asan, and shouldn't be processed again by our unhandled exception
// handler. This value has been created according to the rules here:
// http://msdn.microsoft.com/en-us/library/windows/hardware/ff543026(v=vs.85).aspx
// See winerror.h for more details.
static const DWORD kAsanFacility = 0x68B;  // No more than 11 bits.
static const DWORD kAsanStatus = 0x5AD0;   // No more than 16 bits.
static const DWORD kAsanException =
    (3 << 30) |              // Severity = error.
    (1 << 29) |              // Customer defined code (not defined by MS).
    (kAsanFacility << 16) |  // Facility code.
    kAsanStatus;             // Status code.
static_assert((kAsanFacility >> 11) == 0, "Too many facility bits.");
static_assert((kAsanStatus >> 16) == 0, "Too many status bits.");
static_assert((kAsanException & (3 << 27)) == 0,
              "Bits 27 and 28 should be clear.");

// Raises an exception, first wrapping it an Asan specific exception. This
// indicates to our unhandled exception handler that it doesn't need to
// process the exception.
void RaiseFilteredException(DWORD code,
                            DWORD flags,
                            DWORD num_args,
                            const ULONG_PTR* args) {
  // Retain the original arguments and craft a new exception.
  const ULONG_PTR arguments[4] = {
      code, flags, num_args, reinterpret_cast<const ULONG_PTR>(args)};
  ::RaiseException(kAsanException, 0, ARRAYSIZE(arguments), arguments);
}

// The default error handler. It is expected that this will be bound in a
// callback in the Asan runtime.
// @param context The context when the error has been reported.
// @param error_info The information about this error.
void DefaultErrorHandler(AsanErrorInfo* error_info) {
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);

  ULONG_PTR arguments[] = {reinterpret_cast<ULONG_PTR>(&error_info->context),
                           reinterpret_cast<ULONG_PTR>(error_info)};

  ::DebugBreak();

  // This raises an error in such a way that the Asan unhandled exception
  // handler will not process it.
  RaiseFilteredException(EXCEPTION_ARRAY_BOUNDS_EXCEEDED, 0,
                         ARRAYSIZE(arguments), arguments);
}

// Writes some early crash keys. These will be present even if SyzyAsan crashes
// and can be used to help triage those bugs. This should only be called if a
// reporter exists and supports crash keys.
void SetEarlyCrashKeys(AsanRuntime* runtime) {
  DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
  DCHECK_NE(static_cast<ReporterInterface*>(nullptr),
            runtime->crash_reporter());
  DCHECK_NE(0u, runtime->crash_reporter()->GetFeatures() &
      ReporterInterface::FEATURE_CRASH_KEYS);

  runtime->crash_reporter()->SetCrashKey(
      "asan-crash-reporter",
      runtime->crash_reporter()->GetName());

  runtime->crash_reporter()->SetCrashKey(
      "asan-random-key",
      base::StringPrintf("%016llx", runtime->random_key()).c_str());

  if (runtime->params().feature_randomization) {
    runtime->crash_reporter()->SetCrashKey(
        "asan-feature-set",
        base::UintToString(runtime->GetEnabledFeatureSet()).c_str());
  }
}

// This sets early crash keys for sufficiently modern versions of Chrome that
// are known to support this.
void SetEarlyCrashKeysIfPossible(AsanRuntime* runtime) {
  // To set crash keys we need a crash reporter, and it needs to support early
  // crash key setting.
  if (runtime->crash_reporter() == nullptr)
    return;
  if ((runtime->crash_reporter()->GetFeatures() &
          ReporterInterface::FEATURE_EARLY_CRASH_KEYS) == 0) {
    return;
  }

  // Set a crash key that indicates that early crash keys were successfully
  // set and then set the remaining early crash keys themselves.
  runtime->crash_reporter()->SetCrashKey("asan-early-keys", "true");
  SetEarlyCrashKeys(runtime);
}

// Initializes an exception record for an Asan crash.
void InitializeExceptionRecord(const AsanErrorInfo* error_info,
                               EXCEPTION_RECORD* record,
                               EXCEPTION_POINTERS* pointers) {
  DCHECK_NE(static_cast<AsanErrorInfo*>(nullptr), error_info);
  DCHECK_NE(static_cast<EXCEPTION_RECORD*>(nullptr), record);
  DCHECK_NE(static_cast<EXCEPTION_POINTERS*>(nullptr), pointers);

  ::memset(record, 0, sizeof(EXCEPTION_RECORD));
  record->ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  record->ExceptionAddress = GetInstructionPointer(error_info->context);
  record->NumberParameters = 2;
  record->ExceptionInformation[0] =
      reinterpret_cast<ULONG_PTR>(&error_info->context);
  record->ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(error_info);

  pointers->ExceptionRecord = record;
  pointers->ContextRecord = const_cast<CONTEXT*>(&error_info->context);
}

// Creates a serialized protobuf representing crash data. Also populates
// |memory_ranges| with memory contents related to the crash.
bool PopulateProtobufAndMemoryRanges(const AsanErrorInfo& error_info,
                                     std::string* protobuf,
                                     MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<std::string*>(nullptr), protobuf);
  crashdata::Value value;
  PopulateErrorInfo(AsanRuntime::runtime()->shadow(), error_info, &value,
                    memory_ranges);
  if (!value.SerializeToString(protobuf))
    return false;
  return true;
}

// Send a crash report for the given exception.
void DumpAndCrashViaReporter(AsanErrorInfo* error_info,
                             EXCEPTION_POINTERS* exception_pointers) {
  auto runtime = AsanRuntime::runtime();
  auto reporter = runtime->crash_reporter();
  DCHECK_NE(static_cast<ReporterInterface*>(nullptr), reporter);

  // Set any crash keys.
  if (reporter->GetFeatures() & ReporterInterface::FEATURE_CRASH_KEYS) {
    // Reset the early crash keys, as they may not actually have been set.
    SetEarlyCrashKeys(AsanRuntime::runtime());

    reporter->SetCrashKey("asan-error-type",
                          ErrorInfoAccessTypeToStr(error_info->error_type));

    if (error_info->shadow_info[0] != '\0')
      reporter->SetCrashKey("asan-error-message", error_info->shadow_info);

    if (error_info->asan_parameters.feature_randomization) {
      reporter->SetCrashKey("asan-feature-set",
          base::UintToString(error_info->feature_set).c_str());
    }
  }

  // These are in an outer scope so that they persist until the call to
  // DumpAndCrash.
  std::string protobuf;
  MemoryRanges memory_ranges;

  // Populate the protobuf and the memory regions if possible.
  static const uint32_t kExtraFeatures =
      ReporterInterface::FEATURE_MEMORY_RANGES |
      ReporterInterface::FEATURE_CUSTOM_STREAMS;
  if ((reporter->GetFeatures() & kExtraFeatures) != 0) {
    MemoryRanges* memory_ranges_ptr = nullptr;
    if (reporter->GetFeatures() & ReporterInterface::FEATURE_MEMORY_RANGES)
      memory_ranges_ptr = &memory_ranges;
    PopulateProtobufAndMemoryRanges(*error_info, &protobuf, &memory_ranges);

    if (reporter->GetFeatures() & ReporterInterface::FEATURE_CUSTOM_STREAMS) {
      reporter->SetCustomStream(
          ReporterInterface::kCrashdataProtobufStreamType,
          reinterpret_cast<const uint8_t*>(protobuf.data()),
          protobuf.size());
    }

    // Due to the logic above |memory_ranges| will only be non-empty if
    // the memory range feature is supported.
    if (memory_ranges.size())
      reporter->SetMemoryRanges(memory_ranges);
  }

  // This function should not return.
  reporter->DumpAndCrash(exception_pointers);
  NOTREACHED();
}

// The crash reporting error handler. It is expected that this will be bound in
// a callback in the Asan runtime if a error reporting system is available.
// @param error_info The information about this error.
void CrashReporterErrorHandler(AsanErrorInfo* error_info) {
  EXCEPTION_RECORD exception = {};
  EXCEPTION_POINTERS pointers = {};
  InitializeExceptionRecord(error_info, &exception, &pointers);
  DumpAndCrashViaReporter(error_info, &pointers);
}

// A helper function to find if an intrusive list contains a given entry.
// @param list The list in which we want to look for the entry.
// @param item The entry we want to look for.
// @returns true if the list contains this entry, false otherwise.
bool HeapListContainsEntry(const LIST_ENTRY* list, const LIST_ENTRY* item) {
  LIST_ENTRY* current = list->Flink;
  while (current != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (current->Flink != list) {
      next_item = current->Flink;
    }

    if (current == item) {
      return true;
    }

    current = next_item;
  }
  return false;
}

// A helper function to send a command to Windbg. Windbg should first receive
// the ".ocommand ASAN" command to treat those messages as commands.
void AsanDbgCmd(const wchar_t* fmt, ...) {
  if (!base::debug::BeingDebugged())
    return;
  // The string should start with "ASAN" to be interpreted by the debugger as a
  // command.
  std::wstring command_wstring = L"ASAN ";
  va_list args;
  va_start(args, fmt);

  // Append the actual command to the wstring.
  base::StringAppendV(&command_wstring, fmt, args);

  // Append "; g" to make sure that the debugger continues its execution after
  // executing this command. This is needed because when the .ocommand function
  // is used under Windbg the debugger will break on OutputDebugString.
  command_wstring.append(L"; g");

  OutputDebugString(command_wstring.c_str());
}

// A helper function to print a message to Windbg's console.
void AsanDbgMessage(const wchar_t* fmt, ...) {
  if (!base::debug::BeingDebugged())
    return;
  // Prepend the message with the .echo command so it'll be printed into the
  // debugger's console.
  std::wstring message_wstring = L".echo ";
  va_list args;
  va_start(args, fmt);

  // Append the actual message to the wstring.
  base::StringAppendV(&message_wstring, fmt, args);

  // Treat the message as a command to print it.
  AsanDbgCmd(message_wstring.c_str());
}

// Switch to the caller's context and print its stack trace in Windbg.
void AsanDbgPrintContext(const CONTEXT& context) {
  if (!base::debug::BeingDebugged())
    return;
  AsanDbgMessage(L"Caller's context (%p) and stack trace:", &context);
  AsanDbgCmd(L".cxr %p; kv", reinterpret_cast<uintptr_t>(&context));
}

// Returns the maximum allocation size that can be made safely. This leaves
// space for child function frames, ideally enough for Breakpad to do its
// work.
size_t MaxSafeAllocaSize() {
  // We leave 5KB of stack space for Breakpad and other crash reporting
  // machinery.
  const size_t kReservedStack = 5 * 1024;

  // Find the base of the stack.
  MEMORY_BASIC_INFORMATION mbi = {};
  void* stack = &mbi;
  if (VirtualQuery(stack, &mbi, sizeof(mbi)) == 0)
    return 0;
  size_t max_size = reinterpret_cast<uint8_t*>(stack) -
                    reinterpret_cast<uint8_t*>(mbi.AllocationBase);
  max_size -= std::min(max_size, kReservedStack);
  return max_size;
}

// Performs a dynamic stack allocation of at most |size| bytes. Sets the actual
// size of the allocation and the pointer to it by modifying |size| and |result|
// directly.
#define SAFE_ALLOCA(size, result)          \
  {                                        \
    size_t max_size = MaxSafeAllocaSize(); \
    size = std::min(size, max_size);       \
    result = _alloca(size);                \
    if (result == NULL)                    \
      size = 0;                            \
  }

// Runs the heap checker if enabled. If heap corruption is found serializes
// the results to the stack and modifies the |error_info| structure.
#define CHECK_HEAP_CORRUPTION(runtime, error_info)                          \
  (error_info)->heap_is_corrupt = false;                                    \
  if (!((runtime)->params_.check_heap_on_failure)) {                        \
    runtime_->logger_->Write(                                               \
        "SyzyASAN: Heap checker disabled, ignoring exception.");            \
  } else {                                                                  \
    runtime_->logger_->Write(                                               \
        "SyzyASAN: Heap checker enabled, processing exception.");           \
    AutoHeapManagerLock lock((runtime)->heap_manager_.get());               \
    HeapChecker heap_checker((runtime)->shadow());                          \
    HeapChecker::CorruptRangesVector corrupt_ranges;                        \
    heap_checker.IsHeapCorrupt(&corrupt_ranges);                            \
    size_t size = (runtime)->CalculateCorruptHeapInfoSize(corrupt_ranges);  \
    void* buffer = NULL;                                                    \
    if (size > 0) {                                                         \
      SAFE_ALLOCA(size, buffer);                                            \
      (runtime)                                                             \
          ->WriteCorruptHeapInfo(corrupt_ranges, size, buffer, error_info); \
    }                                                                       \
  }

void LaunchMessageBox(const base::StringPiece& message) {
  // TODO(chrisha): Consider making this close itself with a timeout to prevent
  //     hangs on the waterfall.
  ::MessageBoxA(nullptr, message.data(), nullptr, MB_OK | MB_ICONEXCLAMATION);
}

// Gets the preferred crash reporter type from the environment. This will
// override experiments or command-lines, and is largely meant for local
// testing.
CrashReporterType GetCrashReporterTypeFromEnvironment(
    AsanLogger* logger) {
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger);
  std::unique_ptr<ReporterInterface> reporter;

  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::string reporter_name;
  static const char kSyzyAsanCrashReporterEnv[] =
      "SYZYASAN_CRASH_REPORTER";
  if (!env->GetVar(kSyzyAsanCrashReporterEnv, &reporter_name))
    return kDefaultCrashReporterType;

  CrashReporterType type = kDefaultCrashReporterType;
  if (reporter_name == "crashpad") {
    type = kCrashpadCrashReporterType;
  } else if (reporter_name == "breakpad") {
    type = kBreakpadCrashReporterType;
  }

  if (type != kDefaultCrashReporterType) {
    logger->Write(base::StringPrintf("Encountered %s=\"%s\".",
        kSyzyAsanCrashReporterEnv, reporter_name.c_str()));
  } else {
    logger->Write(base::StringPrintf("Ignoring %s=\"%s\".",
        kSyzyAsanCrashReporterEnv, reporter_name.c_str()));
  }

  return type;
}

// Attempts to create a crash reporter, starting with the most modern.
std::unique_ptr<ReporterInterface> CreateCrashReporterWithTypeHint(
    AsanLogger* logger, CrashReporterType reporter_type) {
  std::unique_ptr<ReporterInterface> reporter;

  // Try to initialize a Crashpad crash reporter.
  if (reporter_type == kCrashpadCrashReporterType ||
      reporter_type == kDefaultCrashReporterType) {
    reporter.reset(reporters::CrashpadReporter::Create().release());
  }

  // If that failed then try to initialize a Breakpad reporter.
  if (reporter.get() == nullptr &&
      (reporter_type == kBreakpadCrashReporterType ||
       reporter_type == kDefaultCrashReporterType)) {
    reporter.reset(reporters::BreakpadReporter::Create().release());
  }

  // Leaving the reporter empty will default to using the system debugger.

  return reporter;
}

}  // namespace

base::Lock AsanRuntime::lock_;
AsanRuntime* AsanRuntime::runtime_ = NULL;
LPTOP_LEVEL_EXCEPTION_FILTER AsanRuntime::previous_uef_ = NULL;
bool AsanRuntime::uef_installed_ = false;

AsanRuntime::AsanRuntime()
    : logger_(),
      stack_cache_(),
      asan_error_callback_(),
      heap_manager_(),
      random_key_(::__rdtsc()),
      crash_reporter_initialized_(false) {
  ::common::SetDefaultAsanParameters(&params_);
  starting_ticks_ = ::GetTickCount();
}

AsanRuntime::~AsanRuntime() {
}

bool AsanRuntime::SetUp(const std::wstring& flags_command_line) {
  base::AutoLock auto_lock(lock_);
  DCHECK(!runtime_);
  runtime_ = this;

  // Setup the shadow memory first. If this fails the dynamic runtime can
  // safely disable the instrumentation.
  if (!SetUpShadow())
    return false;

  // Parse and propagate any flags set via the environment variable. This logs
  // failure for us.
  if (!::common::ParseAsanParameters(flags_command_line, &params_))
    return false;

  // Initialize the command-line structures. This is needed so that
  // SetUpLogger() can include the command-line in the message announcing
  // this process. Note: this is mostly for debugging purposes.
  base::CommandLine::Init(0, NULL);

  // Setup other global state.
  common::StackCapture::Init();
  StackCaptureCache::Init();
  if (!SetUpMemoryNotifier())
    return false;
  if (!SetUpLogger())
    return false;
  if (!SetUpStackCache())
    return false;
  if (!SetUpHeapManager())
    return false;
  WindowsHeapAdapter::SetUp(heap_manager_.get());

  if (params_.feature_randomization) {
    AsanFeatureSet feature_set = GenerateRandomFeatureSet();
    PropagateFeatureSet(feature_set);
  }

  // Propagates the flags values to the different modules.
  PropagateParams();

  if (!params_.defer_crash_reporter_initialization)
    InitializeCrashReporter();

  // Install the unhandled exception handler. This is only installed once
  // across all runtime instances in a process so we check that it hasn't
  // already been installed.
  // TODO(chrisha): Conditionally install this based on the crash reporter in
  // use. Eventually, Crashpad will provide us a callback instead of having us
  // register the handler ourselves.
  if (!uef_installed_) {
    uef_installed_ = true;
    previous_uef_ = ::SetUnhandledExceptionFilter(&UnhandledExceptionFilter);
  }

  // Finally, initialize the heap manager. This comes after parsing all
  // parameters as some decisions can only be made once.
  heap_manager_->Init();

  // Set some early crash keys.
  SetEarlyCrashKeysIfPossible(this);

  return true;
}

void AsanRuntime::TearDown() {
  base::AutoLock auto_lock(lock_);

  // The WindowsHeapAdapter will only have been initialized if the heap manager
  // was successfully created and initialized.
  if (heap_manager_.get() != nullptr)
    WindowsHeapAdapter::TearDown();
  TearDownHeapManager();
  TearDownStackCache();
  TearDownLogger();
  TearDownMemoryNotifier();
  TearDownShadow();
  asan_error_callback_.Reset();

  // Unregister ourselves as the singleton runtime for UEF.
  runtime_ = NULL;

  // In principle, we should also check that all the heaps have been destroyed
  // but this is not guaranteed to be the case in Chrome, so the heap list may
  // not be empty here.
}

void AsanRuntime::OnErrorImpl(AsanErrorInfo* error_info) {
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);

  // Copy the parameters into the crash report.
  error_info->asan_parameters = params_;
  error_info->feature_set = GetEnabledFeatureSet();

  LogAsanErrorInfo(error_info);

  if (params_.minidump_on_failure) {
    DCHECK(logger_.get() != NULL);
    std::string protobuf;
    MemoryRanges memory_ranges;
    PopulateProtobufAndMemoryRanges(*error_info, &protobuf, &memory_ranges);

    logger_->SaveMinidumpWithProtobufAndMemoryRanges(
        &error_info->context, error_info, protobuf, memory_ranges);
  }

  if (params_.exit_on_failure) {
    DCHECK(logger_.get() != NULL);
    logger_->Stop();
    exit(EXIT_FAILURE);
  }
}

void AsanRuntime::OnError(AsanErrorInfo* error_info) {
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);

  // Grab the global page protection lock to prevent page protection settings
  // from being modified while processing the error.
  ::common::AutoRecursiveLock lock(block_protect_lock);

  // Unfortunately this is a giant macro, but it needs to be as it performs
  // stack allocations.
  CHECK_HEAP_CORRUPTION(this, error_info);

  OnErrorImpl(error_info);

  // Call the callback to handle this error.
  DCHECK(!asan_error_callback_.is_null());
  asan_error_callback_.Run(error_info);
}

void AsanRuntime::SetErrorCallBack(const AsanOnErrorCallBack& callback) {
  asan_error_callback_ = callback;
}

bool AsanRuntime::SetUpShadow() {
  // Dynamically allocate the shadow memory.
  shadow_.reset(new Shadow());

  // If the allocation fails, then return false.
  if (shadow_->shadow() == nullptr)
    return false;

#ifndef _WIN64
  // Patch the memory interceptors to refer to the newly allocated shadow.
  // If this fails simply explode because it is unsafe to continue.
  CHECK(PatchMemoryInterceptorShadowReferences(
      asan_memory_interceptors_shadow_memory, shadow_->shadow()));
#endif

  // Setup the shadow and configure the various interceptors to use it.
  shadow_->SetUp();
  agent::asan::SetCrtInterceptorShadow(shadow_.get());
  agent::asan::SetMemoryInterceptorShadow(shadow_.get());
  agent::asan::SetSystemInterceptorShadow(shadow_.get());

  return true;
}

void AsanRuntime::TearDownShadow() {
  // If this didn't successfully initialize then do nothing.
  if (shadow_->shadow() == nullptr)
    return;

  shadow_->TearDown();
  agent::asan::SetCrtInterceptorShadow(nullptr);
  agent::asan::SetMemoryInterceptorShadow(nullptr);
  agent::asan::SetSystemInterceptorShadow(nullptr);
#ifndef _WIN64
  // Unpatch the probes if necessary.
  if (shadow_->shadow() != asan_memory_interceptors_shadow_memory) {
    CHECK(PatchMemoryInterceptorShadowReferences(
        shadow_->shadow(), asan_memory_interceptors_shadow_memory));
  }
#endif
  shadow_.reset();
}

bool AsanRuntime::SetUpMemoryNotifier() {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow_.get());
  DCHECK_NE(static_cast<uint8_t*>(nullptr), shadow_->shadow());
  DCHECK_EQ(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  memory_notifiers::ShadowMemoryNotifier* memory_notifier =
      new memory_notifiers::ShadowMemoryNotifier(shadow_.get());
  memory_notifier->NotifyInternalUse(memory_notifier, sizeof(*memory_notifier));
  memory_notifier_.reset(memory_notifier);
  return true;
}

void AsanRuntime::TearDownMemoryNotifier() {
  if (memory_notifier_.get() == nullptr)
    return;

  memory_notifiers::ShadowMemoryNotifier* memory_notifier =
      reinterpret_cast<memory_notifiers::ShadowMemoryNotifier*>(
          memory_notifier_.get());
  memory_notifier->NotifyReturnedToOS(memory_notifier,
                                      sizeof(*memory_notifier));
  memory_notifier_.reset(nullptr);
}

bool AsanRuntime::SetUpLogger() {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  DCHECK_EQ(static_cast<AsanLogger*>(nullptr), logger_.get());

  // Setup variables we're going to use.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::unique_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  client->set_instance_id(
      base::UTF8ToWide(trace::client::GetInstanceIdForThisModule()));
  client->Init();

  // Register the client singleton instance.
  logger_.reset(client.release());
  memory_notifier_->NotifyInternalUse(logger_.get(), sizeof(*logger_.get()));

  return true;
}

void AsanRuntime::TearDownLogger() {
  if (logger_.get() == nullptr)
    return;

  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  memory_notifier_->NotifyReturnedToOS(logger_.get(), sizeof(*logger_.get()));
  logger_.reset();
}

bool AsanRuntime::SetUpStackCache() {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger_.get());
  DCHECK_EQ(static_cast<StackCaptureCache*>(nullptr), stack_cache_.get());
  stack_cache_.reset(
      new StackCaptureCache(logger_.get(), memory_notifier_.get()));
  memory_notifier_->NotifyInternalUse(stack_cache_.get(),
                                      sizeof(*stack_cache_.get()));

  return true;
}

void AsanRuntime::TearDownStackCache() {
  if (stack_cache_.get() == nullptr)
    return;

  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger_.get());

  stack_cache_->LogStatistics();
  memory_notifier_->NotifyReturnedToOS(stack_cache_.get(),
                                       sizeof(*stack_cache_.get()));
  stack_cache_.reset();
}

bool AsanRuntime::SetUpHeapManager() {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger_.get());
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache_.get());
  DCHECK_EQ(static_cast<heap_managers::BlockHeapManager*>(nullptr),
            heap_manager_.get());

  heap_manager_.reset(new heap_managers::BlockHeapManager(
      shadow(), stack_cache_.get(), memory_notifier_.get()));
  memory_notifier_->NotifyInternalUse(heap_manager_.get(),
                                      sizeof(*heap_manager_.get()));

  // Configure the heap manager to notify us on heap corruption.
  heap_manager_->SetHeapErrorCallback(
      base::Bind(&AsanRuntime::OnError, base::Unretained(this)));

  return true;
}

void AsanRuntime::TearDownHeapManager() {
  if (stack_cache_.get() == nullptr)
    return;

  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr),
            memory_notifier_.get());
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger_.get());
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache_.get());

  // Tear down the heap manager before we destroy it and lose our pointer
  // to it. This is necessary because the heap manager can raise errors
  // while tearing down the heap, which will in turn call back into the
  // block heap manager via the runtime.
  heap_manager_->TearDownHeapManager();
  memory_notifier_->NotifyReturnedToOS(heap_manager_.get(),
                                       sizeof(*heap_manager_.get()));
  heap_manager_.reset();
}

bool AsanRuntime::GetAsanFlagsEnvVar(std::wstring* env_var_wstr) {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string env_var_str;
  if (!env->GetVar(::common::kSyzyAsanOptionsEnvVar, &env_var_str)) {
    return true;
  }

  *env_var_wstr = base::SysUTF8ToWide(env_var_str);

  return true;
}

void AsanRuntime::PropagateParams() {
  // This function has to be kept in sync with the AsanParameters struct. These
  // checks will ensure that this is the case.
#ifdef _WIN64
  static_assert(sizeof(::common::AsanParameters) == 64,
                "Must propagate parameters.");
#else
  static_assert(sizeof(::common::AsanParameters) == 60,
                "Must propagate parameters.");
#endif
  static_assert(::common::kAsanParametersVersion == 15,
                "Must update parameters version.");

  // Push the configured parameter values to the appropriate endpoints.
  heap_manager_->set_parameters(params_);
  StackCaptureCache::set_compression_reporting_period(params_.reporting_period);
  common::StackCapture::set_bottom_frames_to_skip(
      params_.bottom_frames_to_skip);
  stack_cache_->set_max_num_frames(params_.max_num_frames);
  // ignored_stack_ids is used locally by AsanRuntime.
  logger_->set_log_as_text(params_.log_as_text);
  // exit_on_failure is used locally by AsanRuntime.
  logger_->set_minidump_on_failure(params_.minidump_on_failure);
}

size_t AsanRuntime::CalculateCorruptHeapInfoSize(
    const HeapChecker::CorruptRangesVector& corrupt_ranges) {
  size_t n = corrupt_ranges.size() *
             (sizeof(AsanCorruptBlockRange) + sizeof(AsanBlockInfo));
  return n;
}

void AsanRuntime::WriteCorruptHeapInfo(
    const HeapChecker::CorruptRangesVector& corrupt_ranges,
    size_t buffer_size,
    void* buffer,
    AsanErrorInfo* error_info) {
  DCHECK((buffer_size == 0 && buffer == NULL) ||
         (buffer_size != 0 && buffer != NULL));
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);

  ::memset(buffer, 0, buffer_size);

  error_info->heap_is_corrupt = false;
  error_info->corrupt_range_count = 0;
  error_info->corrupt_block_count = 0;
  error_info->corrupt_ranges_reported = 0;
  error_info->corrupt_ranges = NULL;

  if (corrupt_ranges.empty())
    return;

  // If we have corrupt ranges then set the aggregate fields.
  error_info->heap_is_corrupt = true;
  error_info->corrupt_range_count = corrupt_ranges.size();
  for (size_t i = 0; i < corrupt_ranges.size(); ++i)
    error_info->corrupt_block_count += corrupt_ranges[i].block_count;

  // We report a AsanCorruptBlockRange and at least one AsanBlockInfo per
  // corrupt range. Determine how many ranges we can report on.
  size_t range_count =
      buffer_size / (sizeof(AsanCorruptBlockRange) + sizeof(AsanBlockInfo));
  range_count = std::min(range_count, corrupt_ranges.size());

  // Allocate space for the corrupt range metadata.
  uint8_t* cursor = reinterpret_cast<uint8_t*>(buffer);
  uint8_t* buffer_end = cursor + buffer_size;
  error_info->corrupt_ranges = reinterpret_cast<AsanCorruptBlockRange*>(cursor);
  cursor += range_count * sizeof(AsanCorruptBlockRange);
  error_info->corrupt_range_count = corrupt_ranges.size();
  error_info->corrupt_ranges_reported = range_count;

  // Allocate space for the corrupt block metadata.
  size_t block_count = (buffer_end - cursor) / sizeof(AsanBlockInfo);
  AsanBlockInfo* block_infos = reinterpret_cast<AsanBlockInfo*>(cursor);
  cursor += block_count * sizeof(AsanBlockInfo);

  // Write as many corrupt block ranges as we have room for. This is
  // effectively random as it is by order of address.
  for (size_t i = 0; i < range_count; ++i) {
    // Copy the information about the corrupt range.
    error_info->corrupt_ranges[i] = corrupt_ranges[i];

    // Allocate space for the first block of this range on the stack.
    // TODO(sebmarchand): Report more blocks if necessary.
    AsanBlockInfo* asan_block_info = block_infos;
    error_info->corrupt_ranges[i].block_info = block_infos;
    error_info->corrupt_ranges[i].block_info_count = 1;
    ++block_infos;

    // Use a shadow walker to find the first corrupt block in this range and
    // copy its metadata. It's fine for the upper bound address calculation to
    // overflow to 0, as this represents the end of the 4GB address space.
    ShadowWalker shadow_walker(
        shadow(), reinterpret_cast<const uint8_t*>(corrupt_ranges[i].address),
        reinterpret_cast<const uint8_t*>(corrupt_ranges[i].address) +
            corrupt_ranges[i].length);
    BlockInfo block_info = {};
    CHECK(shadow_walker.Next(&block_info));
    // The heap checker removes block protections as it goes, so this block
    // should be readable. However, remove page protections just to be sure.
    // They are left turned off so that the minidump generation can introspect
    // the block.
    BlockProtectNone(block_info, shadow());
    ErrorInfoGetAsanBlockInfo(shadow(), block_info, stack_cache_.get(),
                              asan_block_info);
    DCHECK_EQ(kDataIsCorrupt, asan_block_info->analysis.block_state);
  }

  return;
}

void AsanRuntime::LogAsanErrorInfo(AsanErrorInfo* error_info) {
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), error_info);

  const char* bug_descr = ErrorInfoAccessTypeToStr(error_info->error_type);
  if (logger_->log_as_text()) {
    std::string output(base::StringPrintf(
        "SyzyASAN error: %s on address 0x%08X (stack_id=0x%08X)\n", bug_descr,
        error_info->location, error_info->crash_stack_id));
    if (error_info->access_mode != agent::asan::ASAN_UNKNOWN_ACCESS) {
      const char* access_mode_str = NULL;
      if (error_info->access_mode == agent::asan::ASAN_READ_ACCESS)
        access_mode_str = "READ";
      else
        access_mode_str = "WRITE";
      base::StringAppendF(&output, "%s of size %d at 0x%08X\n", access_mode_str,
                          error_info->access_size, error_info->location);
    }

    // Log the failure and stack.
    logger_->WriteWithContext(output, error_info->context);

    logger_->Write(error_info->shadow_info);
    if (error_info->block_info.free_stack_size != 0U) {
      logger_->WriteWithStackTrace("freed here:\n",
                                   error_info->block_info.free_stack,
                                   error_info->block_info.free_stack_size);
    }
    if (error_info->block_info.alloc_stack_size != NULL) {
      logger_->WriteWithStackTrace("previously allocated here:\n",
                                   error_info->block_info.alloc_stack,
                                   error_info->block_info.alloc_stack_size);
    }
    if (error_info->error_type >= USE_AFTER_FREE) {
      std::string shadow_text;
      shadow()->AppendShadowMemoryText(error_info->location, &shadow_text);
      logger_->Write(shadow_text);
    }
  }

  // Print the base of the Windbg help message.
  AsanDbgMessage(L"An Asan error has been found (%ls), here are the details:",
                 base::SysUTF8ToWide(bug_descr).c_str());

  // Print the Windbg information to display the allocation stack if present.
  if (error_info->block_info.alloc_stack_size != NULL) {
    AsanDbgMessage(L"Allocation stack trace:");
    AsanDbgCmd(L"dps %p l%d", error_info->block_info.alloc_stack,
               error_info->block_info.alloc_stack_size);
  }

  // Print the Windbg information to display the free stack if present.
  if (error_info->block_info.free_stack_size != NULL) {
    AsanDbgMessage(L"Free stack trace:");
    AsanDbgCmd(L"dps %p l%d", error_info->block_info.free_stack,
               error_info->block_info.free_stack_size);
  }
}

// static
AsanFeatureSet AsanRuntime::GenerateRandomFeatureSet() {
  AsanFeatureSet enabled_features =
      static_cast<AsanFeatureSet>(base::RandGenerator(ASAN_FEATURE_MAX));
  DCHECK_LT(enabled_features, ASAN_FEATURE_MAX);
  enabled_features &= kAsanValidFeatures;
  return enabled_features;
}

void AsanRuntime::PropagateFeatureSet(AsanFeatureSet feature_set) {
  DCHECK_EQ(0U, feature_set & ~kAsanValidFeatures);
  heap_manager_->enable_page_protections_ =
      (feature_set & ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS) != 0;
  params_.enable_large_block_heap =
      (feature_set & ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP) != 0;
}

void AsanRuntime::GetBadAccessInformation(AsanErrorInfo* error_info) {
  base::AutoLock lock(lock_);

  // Checks if this is an access to an internal structure or if it's an access
  // in the upper region of the memory (over the 2 GB limit).
  if ((reinterpret_cast<size_t>(error_info->location) >=
       shadow()->memory_size()) ||
      shadow()->GetShadowMarkerForAddress(error_info->location) ==
          kAsanMemoryMarker) {
    error_info->error_type = WILD_ACCESS;
  } else if (shadow()->GetShadowMarkerForAddress(error_info->location) ==
             kInvalidAddressMarker) {
    error_info->error_type = INVALID_ADDRESS;
  } else {
    ErrorInfoGetBadAccessInformation(shadow(), stack_cache_.get(), error_info);
  }
}

bool AsanRuntime::allocation_filter_flag() {
  return heap_manager_->allocation_filter_flag();
}

void AsanRuntime::set_allocation_filter_flag(bool value) {
  heap_manager_->set_allocation_filter_flag(value);
}

void AsanRuntime::AddThreadId(uint32_t thread_id) {
  DCHECK_NE(0u, thread_id);
  base::AutoLock lock(thread_ids_lock_);
  thread_ids_.insert(thread_id);
}

bool AsanRuntime::ThreadIdIsValid(uint32_t thread_id) {
  base::AutoLock lock(thread_ids_lock_);
  return thread_ids_.find(thread_id) != thread_ids_.end();
}

bool AsanRuntime::HeapIdIsValid(HeapManagerInterface::HeapId heap_id) {
  // Consider dying heaps in this query, as they are still valid from the
  // point of view of an error report.
  return heap_manager_->IsValidHeapIdUnlocked(heap_id, true);
}

HeapType AsanRuntime::GetHeapType(HeapManagerInterface::HeapId heap_id) {
  return heap_manager_->GetHeapTypeUnlocked(heap_id);
}

int AsanRuntime::CrashForException(EXCEPTION_POINTERS* exception) {
  return ExceptionFilterImpl(false, exception);
}

LONG WINAPI
AsanRuntime::UnhandledExceptionFilter(struct _EXCEPTION_POINTERS* exception) {
  return ExceptionFilterImpl(true, exception);
}

// static
LONG AsanRuntime::ExceptionFilterImpl(bool is_unhandled,
                                      EXCEPTION_POINTERS* exception) {
  // This ensures that we don't have multiple colliding crashes being processed
  // simultaneously.
  base::AutoLock auto_lock(lock_);

  // Grab the global page protection lock to prevent page protection settings
  // from being modified while processing the error.
  ::common::AutoRecursiveLock lock(block_protect_lock);

  // This is needed for unittesting.
  runtime_->logger_->Write("SyzyASAN: Handling an exception.");

  // If we're bound to a runtime then look for heap corruption and
  // potentially augment the exception record. This needs to exist in the
  // outermost scope of this function as pointers to it may be passed to
  // other exception handlers.
  AsanErrorInfo error_info = {};

  // If this is set to true then an Asan error will be emitted.
  bool emit_asan_error = false;
  // Will be set to true if a near-nullptr access is detected.
  bool near_nullptr_access = false;

  Shadow* shadow = runtime_->shadow();
  // If this is an exception that we launched then extract the original
  // exception data and continue processing it.
  if (exception->ExceptionRecord->ExceptionCode == kAsanException) {
    ULONG_PTR* args = exception->ExceptionRecord->ExceptionInformation;
    DWORD code = args[0];
    DWORD flags = args[1];
    DWORD nargs = args[2];
    const ULONG_PTR* orig_args = reinterpret_cast<const ULONG_PTR*>(args[3]);

    // Rebuild the exception with the original exception data.
    exception->ExceptionRecord->ExceptionCode = code;
    exception->ExceptionRecord->ExceptionFlags = flags;
    exception->ExceptionRecord->NumberParameters = nargs;
    for (DWORD i = 0; i < nargs; ++i)
      args[i] = orig_args[i];
  } else if (runtime_) {
    // Initialize this as if heap corruption is the primary error being
    // reported. This will be overridden by the access violation handling
    // code below, if necessary.
    error_info.location = exception->ExceptionRecord->ExceptionAddress;
    error_info.context = *exception->ContextRecord;
    error_info.error_type = CORRUPT_HEAP;
    error_info.access_mode = ASAN_UNKNOWN_ACCESS;

    // It is possible that access violations are due to page protections of a
    // sufficiently large allocation. In this case the shadow will contain
    // block redzone markers at the given address. We take over the exception
    // if that is the case.
    if (exception->ExceptionRecord->ExceptionCode ==
            EXCEPTION_ACCESS_VIOLATION &&
        exception->ExceptionRecord->NumberParameters >= 2 &&
        exception->ExceptionRecord->ExceptionInformation[0] <= 1) {
      void* address = reinterpret_cast<void*>(
          exception->ExceptionRecord->ExceptionInformation[1]);

      // The first 64k of user memory is unmapped in Windows, we treat those as
      // near-nullptr accesses.
      near_nullptr_access =
          address < reinterpret_cast<void*>(Shadow::kAddressLowerBound);

      ShadowMarker marker = shadow->GetShadowMarkerForAddress(address);
      if ((!near_nullptr_access ||
           runtime_->params().report_invalid_accesses) &&
          ShadowMarkerHelper::IsRedzone(marker) &&
          ShadowMarkerHelper::IsActiveBlock(marker)) {
        BlockInfo block_info = {};
        if (shadow->BlockInfoFromShadow(address, &block_info)) {
          // Page protections have to be removed from this block otherwise our
          // own inspection will cause further errors.
          BlockProtectNone(block_info, runtime_->shadow());

          // Useful for unittesting.
          runtime_->logger_->Write(
              "SyzyASAN: Caught an invalid access via "
              "an access violation exception.");

          // Override the invalid access location with the faulting address,
          // not the code address.
          error_info.location = address;
          // The exact access size isn't reported so simply set it to 1 (an
          // obvious lower bound).
          error_info.access_size = 1;
          // Determine if this is a read or a write using information in the
          // exception record.
          error_info.access_mode =
              exception->ExceptionRecord->ExceptionInformation[0] == 0
                  ? ASAN_READ_ACCESS
                  : ASAN_WRITE_ACCESS;

          // Fill out the rest of the bad access information.
          ErrorInfoGetBadAccessInformation(shadow, runtime_->stack_cache(),
                                           &error_info);
          emit_asan_error = true;
        }
      }
    }

    CHECK_HEAP_CORRUPTION(runtime_, &error_info);
    if (error_info.heap_is_corrupt)
      emit_asan_error = true;
  }

  // If an Asan error was detected then report it via the logger and take over
  // the exception record.
  EXCEPTION_RECORD record = {};
  if (emit_asan_error) {
    if (near_nullptr_access) {
      runtime_->logger_->Write(
          "SyzyASAN: Caught a near-nullptr access with heap corruption.");
    }

    // Log the error via the usual means.
    runtime_->OnErrorImpl(&error_info);

    // Remember the old exception record.
    EXCEPTION_RECORD* old_record = exception->ExceptionRecord;

    // Initialize the exception record and chain the original exception to it.
    InitializeExceptionRecord(&error_info, &record, exception);
    record.ExceptionRecord = old_record;
  } else if (near_nullptr_access &&
             !runtime_->params().report_invalid_accesses) {
    // For unit testing. Record that we ignored a near-nullptr access.
    runtime_->logger_->Write(
        "SyzyASAN: Ignoring a near-nullptr access without heap corruption.");
  }

  // If a crash reporter is present then use it.
  if (emit_asan_error && runtime_->crash_reporter() != nullptr) {
    DumpAndCrashViaReporter(&error_info, exception);
    return EXCEPTION_CONTINUE_SEARCH;
  }

  if (is_unhandled) {
    // Pass the buck to the next exception handler. If the process has an
    // integrated crash reporter that we're not explicitly aware of this will
    // eventually make its way there.
    if (previous_uef_ != NULL)
      return (*previous_uef_)(exception);
  }

  // We can't do anything with this, so let the system deal with it.
  return EXCEPTION_CONTINUE_SEARCH;
}

void AsanRuntime::EnableDeferredFreeThread() {
  DCHECK(heap_manager_);
  heap_manager_->EnableDeferredFreeThread();
}

void AsanRuntime::DisableDeferredFreeThread() {
  DCHECK(heap_manager_);
  heap_manager_->DisableDeferredFreeThread();
}

AsanFeatureSet AsanRuntime::GetEnabledFeatureSet() {
  AsanFeatureSet enabled_features = static_cast<AsanFeatureSet>(0U);
  if (heap_manager_->enable_page_protections_)
    enabled_features |= ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS;
  if (params_.enable_large_block_heap)
    enabled_features |= ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP;

  return enabled_features;
}

void AsanRuntime::InitializeCrashReporter() {
  DCHECK_EQ(nullptr, crash_reporter_.get());
  // Make sure that the crash reporter hasn't already been initialized.
  CHECK(!crash_reporter_initialized_) << "The crash reporter can only "
      "be initialized once.";

  crash_reporter_initialized_ = true;

  // Determine the preferred crash reporter type, as specified in the
  // environment. If this isn't present it defaults to
  // kDefaultCrashReporterType, in which case experiments or command-line flags
  // may specify the crash reporter to use.
  CrashReporterType crash_reporter_type =
      GetCrashReporterTypeFromEnvironment(logger());

  // The name 'disable_breakpad_reporting' is legacy; this actually means to
  // disable all external crash reporting integration.
  if (!params_.disable_breakpad_reporting) {
    // This will create the crash reporter with a preference for creating a
    // reporter of the hinted type. If such a reporter isn't available, it will
    // fall back to trying to create the most 'modern' reporter available.
    crash_reporter_.reset(CreateCrashReporterWithTypeHint(
                              logger(), crash_reporter_type).release());
  }

  // Set up the appropriate error handler depending on whether or not
  // we successfully initialized a crash reporter.
  if (crash_reporter_.get() != nullptr) {
    logger_->Write(base::StringPrintf("SyzyASAN: Using %s for error reporting.",
                                      crash_reporter_->GetName()));
    SetErrorCallBack(base::Bind(&CrashReporterErrorHandler));
  } else {
    logger_->Write("SyzyASAN: Using default error reporting handler.");
    SetErrorCallBack(base::Bind(&DefaultErrorHandler));
  }
}

}  // namespace asan
}  // namespace agent
