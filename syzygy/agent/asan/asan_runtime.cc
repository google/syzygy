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
#include "base/string_util.h"
#include "base/stringprintf.h"
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

// Signatures of the various Breakpad functions for setting custom crash
// key-value pairs.
// Post r194002.
typedef void (__cdecl * SetCrashKeyValuePairPtr)(const char*, const char*);
// Post r217590.
typedef void (__cdecl * SetCrashKeyValueImplPtr)(const wchar_t*,
                                                 const wchar_t*);

// Collects the various Breakpad-related exported functions.
struct BreakpadFunctions {
  // The Breakpad crash reporting entry point.
  WinProcExceptionFilter crash_for_exception_ptr;

  // Various flavours of the custom key-value setting function. The version
  // exported depends on the version of Chrome. It is possible for both of these
  // to be NULL even if crash_for_exception_ptr is not NULL.
  SetCrashKeyValuePairPtr set_crash_key_value_pair_ptr;
  SetCrashKeyValueImplPtr set_crash_key_value_impl_ptr;
};

// The default error handler. It is expected that this will be bound in a
// callback in the ASAN runtime.
// @param context The context when the error has been reported.
// @param error_info The information about this error.
void DefaultErrorHandler(AsanErrorInfo* error_info) {
  DCHECK(error_info != NULL);

  ULONG_PTR arguments[] = {
    reinterpret_cast<ULONG_PTR>(&error_info->context),
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
// If we're running in the context of a breakpad enabled binary we can
// report errors directly via that breakpad entry-point. This allows us
// to report the exact context of the error without including the ASan RTL
// in crash context, depending on where and when we capture the context.
//
// @param breakpad_functions The Breakpad functions structure to be populated.
// @returns true if we found breakpad functions, false otherwise.
bool GetBreakpadFunctions(BreakpadFunctions* breakpad_functions) {
  DCHECK(breakpad_functions != NULL);

  // Clear the structure.
  ::memset(breakpad_functions, 0, sizeof(*breakpad_functions));

  // The named entry-point exposed to report a crash.
  static const char kCrashHandlerSymbol[] = "CrashForException";

  // The named entry-point exposed to annotate a crash with a key/value pair.
  static const char kSetCrashKeyValuePairSymbol[] = "SetCrashKeyValuePair";
  static const char kSetCrashKeyValueImplSymbol[] = "SetCrashKeyValueImpl";

  // Get a handle to the current executable image.
  HMODULE exe_hmodule = ::GetModuleHandle(NULL);

  // Lookup the crash handler symbol.
  breakpad_functions->crash_for_exception_ptr =
      reinterpret_cast<WinProcExceptionFilter>(
          ::GetProcAddress(exe_hmodule, kCrashHandlerSymbol));
  if (breakpad_functions->crash_for_exception_ptr == NULL)
    return false;

  // Lookup the crash annotation symbol.
  breakpad_functions->set_crash_key_value_pair_ptr =
      reinterpret_cast<SetCrashKeyValuePairPtr>(
          ::GetProcAddress(exe_hmodule, kSetCrashKeyValuePairSymbol));
  breakpad_functions->set_crash_key_value_impl_ptr =
      reinterpret_cast<SetCrashKeyValueImplPtr>(
          ::GetProcAddress(exe_hmodule, kSetCrashKeyValueImplSymbol));

  return true;
}

// Sets a crash key using the given breakpad function.
void SetCrashKeyValuePair(const BreakpadFunctions& breakpad_functions,
                          const char* key,
                          const char* value) {
  if (breakpad_functions.set_crash_key_value_pair_ptr != NULL) {
    breakpad_functions.set_crash_key_value_pair_ptr(key, value);
    return;
  }

  if (breakpad_functions.set_crash_key_value_impl_ptr != NULL) {
    std::wstring wkey = UTF8ToWide(key);
    std::wstring wvalue = UTF8ToWide(value);
    breakpad_functions.set_crash_key_value_impl_ptr(wkey.c_str(),
                                                    wvalue.c_str());
    return;
  }

  return;
}

// The breakpad error handler. It is expected that this will be bound in a
// callback in the ASAN runtime.
// @param breakpad_functions A struct containing pointers to the various
//     Breakpad reporting functions.
// @param error_info The information about this error.
void BreakpadErrorHandler(const BreakpadFunctions& breakpad_functions,
                          AsanErrorInfo* error_info) {
  DCHECK(breakpad_functions.crash_for_exception_ptr != NULL);
  DCHECK(error_info != NULL);

  SetCrashKeyValuePair(breakpad_functions,
                       "asan-error-type",
                       HeapProxy::AccessTypeToStr(error_info->error_type));

  if (error_info->shadow_info[0] != '\0') {
    SetCrashKeyValuePair(breakpad_functions,
                         "asan-error-message",
                         error_info->shadow_info);
  }

  EXCEPTION_RECORD exception = {};
  exception.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  exception.ExceptionAddress = reinterpret_cast<PVOID>(
      error_info->context.Eip);
  exception.NumberParameters = 2;
  exception.ExceptionInformation[0] = reinterpret_cast<ULONG_PTR>(
      &error_info->context);
  exception.ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(error_info);

  EXCEPTION_POINTERS pointers = { &exception, &error_info->context };
  breakpad_functions.crash_for_exception_ptr(&pointers);
  NOTREACHED();
}

// Trinary return values used to indicate if a flag was updated or not.
enum FlagResult {
  kFlagNotPresent,
  kFlagSet,
  kFlagError
};

// Try to update the value of a size_t variable from a command-line.
// @param cmd_line The command line who might contain a given parameter.
// @param param_name The parameter that we want to read.
// @param value Will receive the value of the parameter if it's present.
// @returns kFlagNotPresent if the flag was not present and left at its default;
//     kFlagSet if the flag was present, valid and modified; or
//     kFlagError if the flag was present but invalid.
FlagResult UpdateSizetFromCommandLine(const CommandLine& cmd_line,
                                      const std::string& param_name,
                                      size_t* value) {
  DCHECK(value != NULL);
  if (!cmd_line.HasSwitch(param_name))
    return kFlagNotPresent;
  std::string value_str = cmd_line.GetSwitchValueASCII(param_name);
  size_t new_value = 0;
  if (!base::StringToSizeT(value_str, &new_value))
    return kFlagError;
  *value = new_value;

  return kFlagSet;
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

// A helper function to send a command to Windbg. Windbg should first receive
// the ".ocommand ASAN" command to treat those messages as commands.
void ASANDbgCmd(const wchar_t* fmt, ...) {
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
void ASANDbgMessage(const wchar_t* fmt, ...) {
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
  ASANDbgCmd(message_wstring.c_str());
}

// Switch to the caller's context and print its stack trace in Windbg.
void ASANDbgPrintContext(const CONTEXT& context) {
  if (!base::debug::BeingDebugged())
    return;
  ASANDbgMessage(L"Caller's context (%p) and stack trace:", &context);
  ASANDbgCmd(L".cxr %p; kv", reinterpret_cast<uint32>(&context));
}

// Experiment groups.
const size_t kExperimentQuarantineSizes[] = {
  8 * 1024 * 1024,
  16 * 1024 * 1024,  // This is our current default.
  32 * 1024 * 1024,
  64 * 1024 * 1024 };
// Average allocation size is 140 bytes, so each of these has an estimated
// memory process overhead. The header/footer already account for 36 bytes.
const size_t kExperimentTrailerPaddingSizes[] = {
  0,   // 36 byte red zone (25.7% overhead). This is our current default.
  12,  // 48 byte red zone (34.3% overhead).
  28,  // 64 byte red zone (45.7% overhead).
  92   // 128 byte red zone (91.4% overhead).
};

// Gets the value of a coin toss, which is used for putting us into experimental
// groups. We get this value by checking for a SYZYGY_ASAN_COIN_TOSS environment
// variable. If the variable does not exist or is malformed, we consider that
// the client is opted out of experiments. Otherwise, they are opted in and the
// coin toss value (an unsigned 64 bit integer expressed in hex) is returned.
// @param value Will be populated with the coin toss value on success, 0
//     otherwise.
// @returns true if the client is opted in, false otherwise.
bool GetSyzygyAsanCoinToss(uint64* value) {
  DCHECK_NE(reinterpret_cast<uint64*>(NULL), value);

  *value = 0;

  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL)
    return false;

  std::string s;
  if (!env->GetVar(AsanRuntime::kSyzygyAsanCoinTossEnvVar, &s))
    return false;

  if (!base::HexStringToUInt64(s, value))
    return false;

  return true;
}

}  // namespace

const char AsanRuntime::kSyzygyAsanCoinTossEnvVar[] = "SYZYGY_ASAN_COIN_TOSS";
const char AsanRuntime::kSyzygyAsanOptionsEnvVar[] = "SYZYGY_ASAN_OPTIONS";

const char AsanRuntime::kBottomFramesToSkip[] = "bottom_frames_to_skip";
const char AsanRuntime::kCompressionReportingPeriod[] =
    "compression_reporting_period";
const char AsanRuntime::kExitOnFailure[] = "exit_on_failure";
const char AsanRuntime::kIgnoredStackIds[] = "ignored_stack_ids";
const char AsanRuntime::kMaxNumberOfFrames[] = "max_num_frames";
const char AsanRuntime::kMiniDumpOnFailure[] = "minidump_on_failure";
const char AsanRuntime::kNoLogAsText[] = "no_log_as_text";
const char AsanRuntime::kQuarantineSize[] = "quarantine_size";
const wchar_t AsanRuntime::kSyzyAsanDll[] = L"syzyasan_rtl.dll";
const char AsanRuntime::kTrailerPaddingSize[] = "trailer_padding_size";

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
  StackCapture::Init();
  StackCaptureCache::Init();
  SetUpLogger();
  SetUpStackCache();
  HeapProxy::Init(stack_cache_.get());
  if (!ParseFlagsFromString(flags_command_line)) {
    LOG(ERROR) << "Unable to parse the flags from the input string (\""
               << flags_command_line.c_str() << "\").";
  }

  // Propagates the flags values to the different modules.
  PropagateFlagsValues();

  // Register the error reporting callback to use if/when an ASAN error is
  // detected. If we're able to resolve a breakpad error reporting function
  // then use that; otherwise, fall back to the default error handler.
  BreakpadFunctions breakpad_functions = {};
  if (GetBreakpadFunctions(&breakpad_functions)) {
    LOG(INFO) << "SyzyASAN: Using Breakpad for error reporting.";
    SetErrorCallBack(base::Bind(&BreakpadErrorHandler, breakpad_functions));
  } else {
    LOG(INFO) << "SyzyASAN: Using default error reporting handler.";
    SetErrorCallBack(base::Bind(&DefaultErrorHandler));
  }

  // Reporting of the experiment group. This is also reported via Finch/UMA, but
  // we duplicate it to the crash keys for ease of filtering.
  if (flags_.opted_in) {
    SetCrashKeyValuePair(
        breakpad_functions,
        "asan-experiment-quarantine-size",
        base::UintToString(flags_.quarantine_size).c_str());
    SetCrashKeyValuePair(
        breakpad_functions,
        "asan-experiment-trailer-padding-size",
        base::UintToString(flags_.trailer_padding_size).c_str());
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

void AsanRuntime::OnError(AsanErrorInfo* error_info) {
  DCHECK(error_info != NULL);

  const char* bug_descr =
      HeapProxy::AccessTypeToStr(error_info->error_type);
  if (logger_->log_as_text()) {
    std::string output(base::StringPrintf(
        "SyzyASAN error: %s on address 0x%08X (stack_id=0x%08X)\n",
        bug_descr, error_info->location, error_info->crash_stack_id));
    if (error_info->access_mode != HeapProxy::ASAN_UNKNOWN_ACCESS) {
      const char* access_mode_str = NULL;
      if (error_info->access_mode == HeapProxy::ASAN_READ_ACCESS)
        access_mode_str = "READ";
      else
        access_mode_str = "WRITE";
      base::StringAppendF(&output,
                          "%s of size %d at 0x%08X\n",
                          access_mode_str,
                          error_info->access_size);
    }

    // Log the failure and stack.
    logger_->WriteWithContext(output, error_info->context);

    logger_->Write(error_info->shadow_info);
    if (error_info->free_stack_size != 0U) {
      logger_->WriteWithStackTrace("freed here:\n",
                                   error_info->free_stack,
                                   error_info->free_stack_size);
    }
    if (error_info->alloc_stack_size != NULL) {
      logger_->WriteWithStackTrace("previously allocated here:\n",
                                   error_info->alloc_stack,
                                   error_info->alloc_stack_size);
    }
    if (error_info->error_type >= HeapProxy::USE_AFTER_FREE) {
      std::string shadow_text;
      Shadow::AppendShadowMemoryText(error_info->location, &shadow_text);
      logger_->Write(shadow_text);
    }
  }

  // Print the base of the Windbg help message.
  ASANDbgMessage(L"An Asan error has been found (%ls), here are the details:",
                 base::SysUTF8ToWide(bug_descr).c_str());

  // Print the Windbg information to display the allocation stack if present.
  if (error_info->alloc_stack_size != NULL) {
    ASANDbgMessage(L"Allocation stack trace:");
    ASANDbgCmd(L"dps %p l%d",
               error_info->alloc_stack,
               error_info->alloc_stack_size);
  }

  // Print the Windbg information to display the free stack if present.
  if (error_info->free_stack_size != NULL) {
    ASANDbgMessage(L"Free stack trace:");
    ASANDbgCmd(L"dps %p l%d",
               error_info->free_stack,
               error_info->free_stack_size);
  }

  if (flags_.minidump_on_failure) {
    DCHECK(logger_.get() != NULL);
    logger_->SaveMiniDump(&error_info->context, error_info);
  }

  if (flags_.exit_on_failure) {
    DCHECK(logger_.get() != NULL);
    logger_->Stop();
    exit(EXIT_FAILURE);
  }

  // Call the callback to handle this error.
  DCHECK(!asan_error_callback_.is_null());
  asan_error_callback_.Run(error_info);
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

  // Get our experiment status.
  flags_.opted_in = GetSyzygyAsanCoinToss(&flags_.coin_toss);
  uint64 coin_toss = flags_.coin_toss;

  // Parse the quarantine size flag.
  flags_.quarantine_size = HeapProxy::default_quarantine_max_size();
  FlagResult flag_result = UpdateSizetFromCommandLine(
      cmd_line, kQuarantineSize, &flags_.quarantine_size);
  if (flag_result == kFlagError) {
    LOG(ERROR) << "Unable to read " << kQuarantineSize << " from the argument "
               << "list.";
    return false;
  } else if (flag_result == kFlagNotPresent && flags_.opted_in) {
    size_t n = arraysize(kExperimentQuarantineSizes);
    flags_.quarantine_size = kExperimentQuarantineSizes[coin_toss % n];
    coin_toss /= n;
    LOG(INFO) << "Using experiment quarantine size of "
              << flags_.quarantine_size << ".";
  }

  // Parse the trailer padding size flag.
  flags_.trailer_padding_size = 0;
  flag_result = UpdateSizetFromCommandLine(
      cmd_line, kTrailerPaddingSize, &flags_.trailer_padding_size);
  if (flag_result == kFlagError) {
    LOG(ERROR) << "Unable to read " << kTrailerPaddingSize << " from the "
               << "argument list.";
    return false;
  } else if (flag_result == kFlagNotPresent && flags_.opted_in) {
    size_t n = arraysize(kExperimentTrailerPaddingSizes);
    flags_.trailer_padding_size = kExperimentTrailerPaddingSizes[coin_toss % n];
    coin_toss /= n;
    LOG(INFO) << "Using experiment trailer padding size of "
              << flags_.trailer_padding_size << ".";
  }

  // Parse the reporting period flag.
  flags_.reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod();
  if (UpdateSizetFromCommandLine(cmd_line, kCompressionReportingPeriod,
                                 &flags_.reporting_period) == kFlagError) {
    LOG(ERROR) << "Unable to read " << kCompressionReportingPeriod
               << " from the argument list.";
    return false;
  }

  // Parse the bottom frames to skip flag.
  flags_.bottom_frames_to_skip = StackCapture::bottom_frames_to_skip();
  if (UpdateSizetFromCommandLine(cmd_line, kBottomFramesToSkip,
                                 &flags_.bottom_frames_to_skip) == kFlagError) {
    LOG(ERROR) << "Unable to read " << kBottomFramesToSkip << " from the "
               << "argument list.";
    return false;
  }

  // Parse the max number of frames flag.
  flags_.max_num_frames = stack_cache_->max_num_frames();
  if (UpdateSizetFromCommandLine(cmd_line, kMaxNumberOfFrames,
                                 &flags_.max_num_frames) == kFlagError) {
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
  if (!env->GetVar(kSyzygyAsanOptionsEnvVar, &env_var_str)) {
    return true;
  }

  *env_var_wstr = base::SysUTF8ToWide(env_var_str);

  return true;
}

void AsanRuntime::PropagateFlagsValues() const {
  // TODO(sebmarchand): Look into edit-free ways to expose new flags to the
  //     different modules.
  HeapProxy::set_trailer_padding_size(flags_.trailer_padding_size);
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
  DCHECK_NE(reinterpret_cast<HeapProxy*>(NULL), heap);

  // Configure the proxy to notify us on heap corruption.
  heap->SetHeapErrorCallback(
      base::Bind(&AsanRuntime::OnError,
                 base::Unretained(this)));

  {
    base::AutoLock lock(heap_proxy_dlist_lock_);
    InsertTailList(&heap_proxy_dlist_, HeapProxy::ToListEntry(heap));
  }
}

void AsanRuntime::RemoveHeap(HeapProxy* heap) {
  DCHECK_NE(reinterpret_cast<HeapProxy*>(NULL), heap);

  // Clear the callback so that the heap no longer notifies us of errors.
  heap->ClearHeapErrorCallback();

  {
    base::AutoLock lock(heap_proxy_dlist_lock_);
    DCHECK(HeapListContainsEntry(&heap_proxy_dlist_,
                                 HeapProxy::ToListEntry(heap)));
    RemoveEntryList(HeapProxy::ToListEntry(heap));
  }
}

void AsanRuntime::GetBadAccessInformation(AsanErrorInfo* error_info) {
  base::AutoLock lock(heap_proxy_dlist_lock_);

  // Checks if this is an access to an internal structure or if it's an access
  // in the upper region of the memory (over the 2 GB limit).
  if ((reinterpret_cast<size_t>(error_info->location) & (1 << 31)) != 0 ||
      Shadow::GetShadowMarkerForAddress(error_info->location)
          == Shadow::kAsanMemoryByte) {
      error_info->error_type = HeapProxy::WILD_ACCESS;
  } else if (Shadow::GetShadowMarkerForAddress(error_info->location) ==
      Shadow::kInvalidAddress) {
    error_info->error_type = HeapProxy::INVALID_ADDRESS;
  } else {
    // TODO(sebmarchand): Add some code to check if the heap is corrupted.
    HeapProxy::GetBadAccessInformation(error_info);
  }
}

}  // namespace asan
}  // namespace agent
