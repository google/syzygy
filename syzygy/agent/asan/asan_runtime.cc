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

#include "syzygy/agent/asan/asan_runtime.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/utf_string_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/sys_string_conversions.h"
#include "base/win/pe_image.h"
#include "base/win/wrapped_window_proc.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanLogger;
using agent::asan::HeapProxy;
using agent::asan::StackCaptureCache;
using base::win::WinProcExceptionFilter;

typedef void  (__cdecl * SetCrashKeyValueFuncPtr)(const char*, const char*);

// The default error handler. It is expected that this will be bound in a
// callback in the ASAN runtime.
// @param context The context when the error has been reported.
// @param error_info The information about this error.
void DefaultErrorHandler(CONTEXT* context, AsanErrorInfo* error_info) {
  DCHECK(context != NULL);
  DCHECK(error_info != NULL);

  ULONG_PTR arguments[] = {
    reinterpret_cast<ULONG_PTR>(context),
    reinterpret_cast<ULONG_PTR>(error_info)
  };

  ::DebugBreak();
  ::RaiseException(EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
                   0,
                   ARRAYSIZE(arguments),
                   &arguments[0]);
}

// Returns the breakpad crash reporting functions if breakpad is enabled for
// the current executable.
//
// @param crash_func A pointer to a crash reporting function will be returned
//     here, or NULL.
// @param key_value_func A pointer to a function to set additional key/value
//     attributes for the crash before calling crash_func, or NULL. This may
//     return NULL even if crash_func returns non-NULL.
//
// If we're running in the context of a breakpad enabled binary we can
// report errors directly via that breakpad entry-point. This allows us
// to report the exact context of the error without including the asan_rtl
// in crash context, depending on where and when we capture the context.
void GetBreakpadFunctions(WinProcExceptionFilter* crash_func,
                          SetCrashKeyValueFuncPtr* key_value_func ) {
  DCHECK(crash_func != NULL);
  DCHECK(key_value_func != NULL);

  // The named entry-point exposed to report a crash.
  static const char kCrashHandlerSymbol[] = "CrashForException";

  // The named entry-point exposed to annotate a crash with a key/value pair.
  static const char kSetCrashKeyValueSymbol[] = "SetCrashKeyValuePair";

  // Get a handle to the current executable image.
  HMODULE exe_hmodule = ::GetModuleHandle(NULL);

  // Lookup the crash handler symbol.
  *crash_func = reinterpret_cast<WinProcExceptionFilter>(
      ::GetProcAddress(exe_hmodule, kCrashHandlerSymbol));

  // Lookup the crash annotation symbol.
  *key_value_func = reinterpret_cast<SetCrashKeyValueFuncPtr>(
      ::GetProcAddress(exe_hmodule, kSetCrashKeyValueSymbol));
}

// The breakpad error handler. It is expected that this will be bound in a
// callback in the ASAN runtime.
// @param func_ptr A pointer to the breakpad error reporting function. This
//     will be used to perform the error reporting.
// @param crash_func_ptr A pointer to the breakpad crash reporting function.
// @param key_value_func A pointer to a function to set additional key/value
//     attributes for the crash before calling crash_func. For backwards
//     compatibility, with older breakpad clients, this parameter is optional
//     (it may be NULL).
// @param context The context when the error has been reported.
// @param error_info The information about this error.
void BreakpadErrorHandler(WinProcExceptionFilter crash_func_ptr,
                          SetCrashKeyValueFuncPtr set_key_value_func_ptr,
                          CONTEXT* context,
                          AsanErrorInfo* error_info) {
  DCHECK(crash_func_ptr != NULL);
  DCHECK(context != NULL);
  DCHECK(error_info != NULL);

  if (set_key_value_func_ptr != NULL) {
    set_key_value_func_ptr(
        "asan-error-type",
        HeapProxy::AccessTypeToStr(error_info->error_type));
    if (error_info->shadow_info[0] != '\0') {
      set_key_value_func_ptr(
          "asan-error-message", error_info->shadow_info);
    }
  }

  EXCEPTION_RECORD exception = {};
  exception.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  exception.ExceptionAddress = reinterpret_cast<PVOID>(context->Eip);
  exception.NumberParameters = 2;
  exception.ExceptionInformation[0] = reinterpret_cast<ULONG_PTR>(context);
  exception.ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(error_info);

  EXCEPTION_POINTERS pointers = { &exception, context };
  crash_func_ptr(&pointers);
  NOTREACHED();
}

// Try to update the value of a size_t variable from a command-line.
// @param cmd_line The command line who might contain a given parameter.
// @param param_name The parameter that we want to read.
// @param value Will receive the value of the parameter if it's present.
// @returns true on success, false otherwise.
bool UpdateSizetFromCommandLine(const CommandLine& cmd_line,
                                const std::string& param_name,
                                size_t* value) {
  DCHECK(value != NULL);
  if (!cmd_line.HasSwitch(param_name))
    return true;
  std::string value_str = cmd_line.GetSwitchValueASCII(param_name);
  size_t new_value = 0;
  if (!base::StringToSizeT(value_str, &new_value))
    return false;
  *value = new_value;

  return true;
}

// Try to update the value of an array of ignored stack ids from a command-line.
// We expect the values to be in hexadecimal format and separated by a
// semi-colon.
// @param cmd_line The command line to parse.
// @param param_name The parameter that we want to read.
// @param values Will receive the set of parsed values.
// @returns true on success, false otherwise.
bool ReadIgnoredStackIdsFromCommandLine(const CommandLine& cmd_line,
                                        const std::string& param_name,
                                        AsanRuntime::StackIdSet* values) {
  DCHECK(values != NULL);
  if (!cmd_line.HasSwitch(param_name))
    return true;
  std::string value_str = cmd_line.GetSwitchValueASCII(param_name);
  base::StringTokenizer string_tokenizer(value_str, ";");
  while (string_tokenizer.GetNext()) {
    int64 new_value = 0;
    if (!base::HexStringToInt64(string_tokenizer.token(), &new_value))
      return false;
    values->insert(static_cast<StackCapture::StackId>(new_value));
  }
  return true;
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

// Check if the current process is large address aware.
// @returns true if it is, false otherwise.
bool CurrentProcessIsLargeAddressAware() {
  const base::win::PEImage image(::GetModuleHandle(NULL));

  bool process_is_large_address_aware =
    (image.GetNTHeaders()->FileHeader.Characteristics &
        IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;

  return process_is_large_address_aware;
}

}  // namespace

const char AsanRuntime::kSyzyAsanEnvVar[] = "SYZYGY_ASAN_OPTIONS";

const char AsanRuntime::kBottomFramesToSkip[] =
    "bottom_frames_to_skip";
const char AsanRuntime::kCompressionReportingPeriod[] =
    "compression_reporting_period";
const char AsanRuntime::kExitOnFailure[] = "exit_on_failure";
const char AsanRuntime::kIgnoredStackIds[] = "ignored_stack_ids";
const char AsanRuntime::kMaxNumberOfFrames[] = "max_num_frames";
const char AsanRuntime::kMiniDumpOnFailure[] = "minidump_on_failure";
const char AsanRuntime::kNoLogAsText[] = "no_log_as_text";
const char AsanRuntime::kQuarantineSize[] = "quarantine_size";
const wchar_t AsanRuntime::kSyzyAsanDll[] = L"asan_rtl.dll";

AsanRuntime::AsanRuntime()
    : logger_(NULL), stack_cache_(NULL), asan_error_callback_(), flags_(),
      heap_proxy_dlist_lock_(), heap_proxy_dlist_() {
}

AsanRuntime::~AsanRuntime() {
}

void AsanRuntime::SetUp(const std::wstring& flags_command_line) {
  // Ensure that the current process is not large address aware. It shouldn't be
  // because the shadow memory assume that the process will only be able to use
  // 2GB of address space.
  CHECK(!CurrentProcessIsLargeAddressAware());

  // Initialize the command-line structures. This is needed so that
  // SetUpLogger() can include the command-line in the message announcing
  // this process. Note: this is mostly for debugging purposes.
  CommandLine::Init(0, NULL);

  Shadow::SetUp();

  InitializeListHead(&heap_proxy_dlist_);

  // Setup the "global" state.
  HeapProxy::Init();
  StackCapture::Init();
  StackCaptureCache::Init();
  SetUpLogger();
  SetUpStackCache();
  if (!ParseFlagsFromString(flags_command_line)) {
    LOG(ERROR) << "Unable to parse the flags from the input string (\""
               << flags_command_line.c_str() << "\").";
  }
  // Propagates the flags values to the different modules.
  PropagateFlagsValues();

  // Register the error reporting callback to use if/when an ASAN error is
  // detected. If we're able to resolve a breakpad error reporting function
  // then use that; otherwise, fall back to the default error handler.
  WinProcExceptionFilter crash_func_ptr = NULL;
  SetCrashKeyValueFuncPtr set_key_value_func_ptr = NULL;
  GetBreakpadFunctions(&crash_func_ptr, &set_key_value_func_ptr);
  if (crash_func_ptr != NULL) {
    LOG(INFO) << "SyzyASAN: Using Breakpad for error reporting.";
    SetErrorCallBack(base::Bind(
        &BreakpadErrorHandler, crash_func_ptr, set_key_value_func_ptr));
  } else {
    LOG(INFO) << "SyzyASAN: Using default error reporting handler.";
    SetErrorCallBack(base::Bind(&DefaultErrorHandler));
  }
}

void AsanRuntime::TearDown() {
  TearDownStackCache();
  TearDownLogger();
  DCHECK(asan_error_callback_.is_null() == FALSE);
  asan_error_callback_.Reset();
  Shadow::TearDown();
  // In principle, we should also check that all the heaps have been destroyed
  // but this is not guaranteed to be the case in Chrome, so the heap list may
  // not be empty here.
}

void AsanRuntime::OnError(CONTEXT* context, AsanErrorInfo* error_info) {
  DCHECK(context != NULL);

  if (flags_.minidump_on_failure) {
    DCHECK(logger_.get() != NULL);
    logger_->SaveMiniDump(context, error_info);
  }

  if (flags_.exit_on_failure) {
    DCHECK(logger_.get() != NULL);
    logger_->Stop();
    exit(EXIT_FAILURE);
  }

  // Call the callback to handle this error.
  DCHECK(!asan_error_callback_.is_null());
  asan_error_callback_.Run(context, error_info);
}

void AsanRuntime::SetErrorCallBack(const AsanOnErrorCallBack& callback) {
  asan_error_callback_ = callback;
}

void AsanRuntime::SetUpLogger() {
  // Setup variables we're going to use.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  scoped_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  client->set_instance_id(
      UTF8ToWide(trace::client::GetInstanceIdForThisModule()));
  client->Init();

  // Register the client singleton instance.
  logger_.reset(client.release());
}

void AsanRuntime::TearDownLogger() {
  logger_.reset();
}

void AsanRuntime::SetUpStackCache() {
  DCHECK(stack_cache_.get() == NULL);
  DCHECK(logger_.get() != NULL);
  stack_cache_.reset(new StackCaptureCache(logger_.get()));
}

void AsanRuntime::TearDownStackCache() {
  DCHECK(stack_cache_.get() != NULL);
  stack_cache_->LogStatistics();
  stack_cache_.reset();
}

bool AsanRuntime::ParseFlagsFromString(std::wstring str) {
  // Prepends the flags with the agent name. We need to do this because the
  // command-line constructor expect the process name to be the first value of
  // the command-line string.
  // Start by inserting a space at the beginning of the flags to separate the
  // flags from the agent name.
  str.insert(0, L" ");
  // Insert the agent name.
  str.insert(0, kSyzyAsanDll);

  CommandLine cmd_line = CommandLine::FromString(str);

  // Parse the quarantine size flag.
  flags_.quarantine_size = HeapProxy::default_quarantine_max_size();
  if (!UpdateSizetFromCommandLine(cmd_line, kQuarantineSize,
                                  &flags_.quarantine_size)) {
    LOG(ERROR) << "Unable to read " << kQuarantineSize << " from the argument "
               << "list.";
    return false;
  }

  // Parse the reporting period flag.
  flags_.reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod();
  if (!UpdateSizetFromCommandLine(cmd_line, kCompressionReportingPeriod,
                                  &flags_.reporting_period)) {
    LOG(ERROR) << "Unable to read " << kCompressionReportingPeriod
               << " from the argument list.";
    return false;
  }

  // Parse the bottom frames to skip flag.
  flags_.bottom_frames_to_skip = StackCapture::bottom_frames_to_skip();
  if (!UpdateSizetFromCommandLine(cmd_line, kBottomFramesToSkip,
                                  &flags_.bottom_frames_to_skip)) {
    LOG(ERROR) << "Unable to read " << kBottomFramesToSkip << " from the "
               << "argument list.";
    return false;
  }

  // Parse the max number of frames flag.
  flags_.max_num_frames = stack_cache_->max_num_frames();
  if (!UpdateSizetFromCommandLine(cmd_line, kMaxNumberOfFrames,
                                  &flags_.max_num_frames)) {
    LOG(ERROR) << "Unable to read " << kMaxNumberOfFrames << " from the "
               << "argument list.";
    return false;
  }

  // Parse the ignored stack ids.
  if (!ReadIgnoredStackIdsFromCommandLine(cmd_line, kIgnoredStackIds,
                                          &flags_.ignored_stack_ids)) {
    LOG(ERROR) << "Unable to read " << kIgnoredStackIds << " from the "
               << "argument list.";
    return false;
  }

  // Parse the other (boolean) flags.
  flags_.exit_on_failure = cmd_line.HasSwitch(kExitOnFailure);
  flags_.minidump_on_failure = cmd_line.HasSwitch(kMiniDumpOnFailure);
  flags_.log_as_text = !cmd_line.HasSwitch(kNoLogAsText);

  return true;
}

bool AsanRuntime::GetAsanFlagsEnvVar(std::wstring* env_var_wstr) {
  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string env_var_str;
  if (!env->GetVar(kSyzyAsanEnvVar, &env_var_str)) {
    return true;
  }

  *env_var_wstr = base::SysUTF8ToWide(env_var_str);

  return true;
}

void AsanRuntime::PropagateFlagsValues() const {
  // TODO(sebmarchand): Look into edit-free ways to expose new flags to the
  //     different modules.
  HeapProxy::set_default_quarantine_max_size(flags_.quarantine_size);
  StackCapture::set_bottom_frames_to_skip(flags_.bottom_frames_to_skip);
  StackCaptureCache::set_compression_reporting_period(flags_.reporting_period);
  stack_cache_->set_max_num_frames(flags_.max_num_frames);
  logger_->set_log_as_text(flags_.log_as_text);
  logger_->set_minidump_on_failure(flags_.minidump_on_failure);
}

void AsanRuntime::set_flags(const AsanFlags* flags) {
  DCHECK(flags != NULL);
  flags_ = *flags;
}

void AsanRuntime::AddHeap(HeapProxy* heap) {
  base::AutoLock lock(heap_proxy_dlist_lock_);
  InsertTailList(&heap_proxy_dlist_, HeapProxy::ToListEntry(heap));
}

void AsanRuntime::RemoveHeap(HeapProxy* heap) {
  base::AutoLock lock(heap_proxy_dlist_lock_);
  DCHECK(HeapListContainsEntry(&heap_proxy_dlist_,
                               HeapProxy::ToListEntry(heap)));
  RemoveEntryList(HeapProxy::ToListEntry(heap));
}

void AsanRuntime::ReportAsanErrorDetails(const void* addr,
                                         const CONTEXT& context,
                                         const StackCapture& stack,
                                         HeapProxy::AccessMode access_mode,
                                         size_t access_size,
                                         AsanErrorInfo* bad_access_info) {
  DCHECK(bad_access_info != NULL);
  base::AutoLock lock(heap_proxy_dlist_lock_);
  // Iterates over the HeapProxy list to find the memory block containing this
  // address. We expect that there is at least one heap proxy extant.
  HeapProxy* proxy = NULL;
  LIST_ENTRY* item = heap_proxy_dlist_.Flink;
  CHECK(item != NULL);
  while (item != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (item->Flink != &heap_proxy_dlist_) {
      next_item = item->Flink;
    }

    proxy = HeapProxy::FromListEntry(item);
    if (proxy->OnBadAccess(addr,
                           context,
                           stack,
                           access_mode,
                           access_size,
                           bad_access_info)) {
      break;
    }

    item = next_item;
  }

  // If item is NULL then we went through the list without finding the heap
  // from which this address was allocated. We can just reuse the logger of
  // the last heap proxy we saw to report an "unknown" error.
  if (item == NULL) {
    bad_access_info->error_type = HeapProxy::UNKNOWN_BAD_ACCESS;
    CHECK(proxy != NULL);
    proxy->ReportUnknownError(addr, context, stack, access_mode,
                              access_size);
  }
}

}  // namespace asan
}  // namespace agent
