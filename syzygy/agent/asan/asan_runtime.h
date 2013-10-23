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
//
// A class that take care of initializing asan run-time library.

#ifndef SYZYGY_AGENT_ASAN_ASAN_RUNTIME_H_
#define SYZYGY_AGENT_ASAN_ASAN_RUNTIME_H_

#include <set>
#include <string>

#include "base/callback.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/common/dlist.h"

namespace agent {
namespace asan {

class AsanLogger;

// Store the information about a bad memory access.
struct AsanErrorInfo {
  // The address where the bad access happened.
  void* location;
  // The context prior to the crash.
  CONTEXT context;
  // The allocation stack trace.
  void* alloc_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The size of the allocation stack trace.
  uint8 alloc_stack_size;
  // The ID of the allocation thread.
  DWORD alloc_tid;
  // The free stack trace.
  void* free_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The size of the free stack trace.
  uint8 free_stack_size;
  // The ID of the free thread.
  DWORD free_tid;
  // The ID of the crash stack, this is needed to be able to blacklist some
  // known bugs.
  StackCapture::StackId crash_stack_id;
  // The error type.
  HeapProxy::BadAccessKind error_type;
  // The access mode.
  HeapProxy::AccessMode access_mode;
  // The access size.
  size_t access_size;
  // The information about the shadow memory for this address, this would be
  // something like: "0x12345678 is located 8 bytes inside of 10-bytes region
  // [0x12345670,0x1234567A)."
  char shadow_info[128];
  // A textual description of the shadow memory around |location|.
  char shadow_memory[512];
  // The time since the memory block containing this address has been freed.
  // This would be equal to zero if the block is still allocated.
  uint64 microseconds_since_free;
};

// An Asan Runtime manager.
// This class takes care of initializing the different modules (stack cache,
// logger...) and provide the functions to report an error.
// Basic usage:
//     AsanRuntime* asan_runtime = new AsanRuntime();
//     std::wstring asan_flags_str;
//     AsanRuntime::GetAsanFlagsEnvVar(&asan_flags_str);
//     asan_runtime->SetUp(asan_flags_str);  // Initialize the modules.
//     ...
//     AsanErrorInfo bad_access_info = {};
//     ::RtlCaptureContext(&bad_access_info.context);
//     StackCapture stack;
//     stack.InitFromStack();
//     stack.set_stack_id(stack.ComputeRelativeStackId());
//     bad_access_info.crash_stack_id = stack.stack_id();
//     asan_runtime->OnError(&bad_access_info);
//     asan_runtime->TearDown();  // Release the modules.
//     delete asan_runtime;
class AsanRuntime {
 public:
  typedef std::set<StackCapture::StackId> StackIdSet;

  // The type of callback used by the OnError function.
  typedef base::Callback<void(AsanErrorInfo*)> AsanOnErrorCallBack;

  AsanRuntime();
  ~AsanRuntime();

  // @name Accessors.
  // @{
  AsanLogger* logger() {
    DCHECK(logger_.get() != NULL);
    return logger_.get();
  }
  StackCaptureCache* stack_cache() {
    DCHECK(stack_cache_.get() != NULL);
    return stack_cache_.get();
  }
  static const wchar_t* SyzyAsanDll() {
    return kSyzyAsanDll;
  }
  // @}

  // Initialize asan runtime library.
  // @param flags_command_line The parameters string.
  void SetUp(const std::wstring& flags_command_line);

  // Release asan runtime library.
  void TearDown();

  // The error handler.
  // @param error_info The information about this error.
  void OnError(AsanErrorInfo* error_info);

  // Set the callback called on error.
  // TODO(sebmarchand): Move the signature of this callback to an header file
  //     so it'll be easier to update it.
  void SetErrorCallBack(const AsanOnErrorCallBack& callback);

  // Try to read the Asan environment variable.
  // @param env_var_wstr The wstring where to store the environment variable.
  // returns true on success, false otherwise.
  static bool GetAsanFlagsEnvVar(std::wstring* env_var_wstr);

  // Add an heap proxy to the heap proxies list.
  void AddHeap(HeapProxy* heap);

  // Remove an heap proxy from the heap proxies list.
  void RemoveHeap(HeapProxy* heap);

  // Returns true if we should ignore the given @p stack_id, false
  // otherwise.
  bool ShouldIgnoreError(size_t stack_id) const {
    // TODO(sebmarchand): Keep a list of the stack ids that have already been
    //     reported so we can avoid reporting the same error multiple times.
    return flags_.ignored_stack_ids.find(stack_id) !=
        flags_.ignored_stack_ids.end();
  }

  // Get information about a bad access.
  // @param bad_access_info Will receive the information about this access.
  void GetBadAccessInformation(AsanErrorInfo* error_info);

  // The name of the environment variable holding the experiment opt-in coin
  // toss value.
  static const char kSyzygyAsanCoinTossEnvVar[];

  // The name of the environment variable containing the command-line.
  static const char kSyzygyAsanOptionsEnvVar[];

 protected:
  // A structure to track the values of the flags.
  struct AsanFlags {
    AsanFlags()
        : quarantine_size(0U),
          reporting_period(0U),
          bottom_frames_to_skip(0U),
          max_num_frames(0U),
          trailer_padding_size(0U),
          exit_on_failure(false),
          minidump_on_failure(false),
          log_as_text(true),
          opted_in(false),
          coin_toss(0) {
    }

    // The default size of the quarantine of the HeapProxy, in bytes.
    size_t quarantine_size;

    // The number of allocations between reports of the stack trace cache
    // compression ratio.
    size_t reporting_period;

    // The number of bottom frames to skip on a stack trace.
    size_t bottom_frames_to_skip;

    // The max number of frames for a stack trace.
    size_t max_num_frames;

    // The size of the padding added to every memory block trailer.
    size_t trailer_padding_size;

    // The stack ids we ignore.
    StackIdSet ignored_stack_ids;

    // If true, we should generate a minidump whenever an error is detected.
    // Defaults to false.
    bool minidump_on_failure;

    // If we should stop the logger (and the running program) after reporting
    // an error. Defaults to false.
    bool exit_on_failure;

    // If true, we should generate a textual log describing any errors.
    // Defaults to true;
    bool log_as_text;

    // Experiment configuration.
    bool opted_in;
    uint64 coin_toss;
  };

  // @name Flag strings.
  // @{
  static const char kBottomFramesToSkip[];
  static const char kCompressionReportingPeriod[];
  static const char kExitOnFailure[];
  static const char kIgnoredStackIds[];
  static const char kMaxNumberOfFrames[];
  static const char kMiniDumpOnFailure[];
  static const char kNoLogAsText[];
  static const char kQuarantineSize[];
  static const wchar_t kSyzyAsanDll[];
  static const char kTrailerPaddingSize[];
  // @}

  // @name Accessors.
  // @{
  const AsanFlags* const flags() { return &flags_; }
  // @}

  // @name Mutators.
  // @{
  void set_flags(const AsanFlags* flags);
  // @}

  // Propagate the values of the flags to the target modules.
  void PropagateFlagsValues() const;

 private:
  // Set up the logger.
  void SetUpLogger();

  // Tear down the logger.
  void TearDownLogger();

  // Set up the stack cache.
  void SetUpStackCache();

  // Tear down the stack cache.
  void TearDownStackCache();

  // Parse and set the flags from the wide string @p str.
  bool ParseFlagsFromString(std::wstring str);

  // The shared logger instance that will be used by all heap proxies.
  scoped_ptr<AsanLogger> logger_;

  // The shared stack cache instance that will be used by all heap proxies.
  scoped_ptr<StackCaptureCache> stack_cache_;

  // The asan error callback functor.
  AsanOnErrorCallBack asan_error_callback_;

  // The values of the flags.
  AsanFlags flags_;

  // The heap proxies list lock.
  base::Lock heap_proxy_dlist_lock_;

  // The heap proxies list.
  LIST_ENTRY heap_proxy_dlist_;  // Under heap_proxy_dlist_lock.

  DISALLOW_COPY_AND_ASSIGN(AsanRuntime);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_RUNTIME_H_
