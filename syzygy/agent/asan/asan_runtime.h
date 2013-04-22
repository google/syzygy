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
class StackCaptureCache;

// Store the information about a bad memory access.
// TODO(sebmarchand): Add an array with the copy of the shadow memory around
//     this bad access.
struct AsanErrorInfo {
  void* alloc_stack[agent::asan::StackCapture::kMaxNumFrames];
  uint8 alloc_stack_size;
  void* free_stack[agent::asan::StackCapture::kMaxNumFrames];
  uint8 free_stack_size;
  HeapProxy::BadAccessKind error_type;
  HeapProxy::AccessMode access_mode;
  size_t access_size;
  char shadow_info[128];
  uint64 microseconds_since_free;
};

// An Asan Runtime manager.
// This class take care of initializing the different modules (stack cache,
// logger...) and provide the functions to report an error.
// Basic usage:
//     AsanRuntime* asan_runtime = new AsanRuntime();
//     std::wstring asan_flags_str;
//     AsanRuntime::GetAsanFlagsEnvVar(&asan_flags_str);
//     asan_runtime->SetUp(asan_flags_str);  // Initialize the modules.
//     ...
//     CONTEXT context;
//     ::RtlCaptureContext(&context);
//     StackCapture stack;
//     stack.InitFromStack();
//     stack.set_stack_id(stack.ComputeRelativeStackId());
//     asan_runtime->OnError((&context, stack.stack_id());
//     asan_runtime->TearDown();  // Release the modules.
//     delete asan_runtime;
class AsanRuntime {
 public:
  typedef std::set<StackCapture::StackId> StackIdSet;

  // The type of callback used by the OnError function.
  typedef base::Callback<void(CONTEXT*, AsanErrorInfo*)> AsanOnErrorCallBack;

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
  // @param context The context when the error has been reported.
  // @param error_info The information about this error.
  void OnError(CONTEXT* context, AsanErrorInfo* error_info);

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

  // Report the details of an Asan error by walking the heap proxies list.
  // @param addr The red-zoned address causing a bad access.
  // @param context The context at which the access occurred.
  // @param stack The stack capture at the point of error.
  // @param access_mode The kind of the access (read or write).
  // @param access_size The size of the access (in bytes).
  // @param bad_access_info Will receive the information about this access.
  void ReportAsanErrorDetails(const void* addr,
                              const CONTEXT& context,
                              const StackCapture& stack,
                              HeapProxy::AccessMode access_mode,
                              size_t access_size,
                              AsanErrorInfo* bad_access_info);

  // Returns true if we should ignore the given @p stack_id, false
  // otherwise.
  bool ShouldIgnoreError(size_t stack_id) const {
    // TODO(sebmarchand): Keep a list of the stack ids that have already been
    //     reported so we can avoid reporting the same error multiple times.
    return flags_.ignored_stack_ids.find(stack_id) !=
        flags_.ignored_stack_ids.end();
  }

 protected:
  // A structure to track the values of the flags.
  struct AsanFlags {
    AsanFlags()
        : quarantine_size(0U),
          reporting_period(0U),
          bottom_frames_to_skip(0U),
          max_num_frames(0U),
          exit_on_failure_(false) {
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

    // The stack ids we ignore.
    StackIdSet ignored_stack_ids;

    // Indicates if we should just exit on error rather than calling the error
    // handler. Default to false.
    bool exit_on_failure_;
  };

  // The name of the environment variable containing the command-line.
  static const char kSyzyAsanEnvVar[];

  // @name Flag strings.
  // @{
  static const char kBottomFramesToSkip[];
  static const char kCompressionReportingPeriod[];
  static const char kExitOnFailure[];
  static const char kIgnoredStackIds[];
  static const char kMaxNumberOfFrames[];
  static const char kQuarantineSize[];
  static const wchar_t kSyzyAsanDll[];
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
