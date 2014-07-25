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
#include "syzygy/agent/asan/asan_heap_checker.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/agent/common/dlist.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {

// Forward declarations.
class AsanLogger;

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

  typedef std::vector<HeapProxy*> HeapVector;

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
  bool ShouldIgnoreError(common::AsanStackId stack_id) const {
    // TODO(sebmarchand): Keep a list of the stack ids that have already been
    //     reported so we can avoid reporting the same error multiple times.
    return params_.ignored_stack_ids_set.find(stack_id) !=
        params_.ignored_stack_ids_set.end();
  }

  // Get information about a bad access.
  // @param bad_access_info Will receive the information about this access.
  void GetBadAccessInformation(AsanErrorInfo* error_info);

  // The name of the environment variable containing the command-line.
  static const char kSyzygyAsanOptionsEnvVar[];

  // Accessors for runtime parameters.
  common::InflatedAsanParameters& params() { return params_; }
  const common::InflatedAsanParameters& params() const { return params_; }

  // Fill a vector with all the active heaps.
  // @param heap_vector Will receive the active heaps.
  void GetHeaps(HeapVector* heap_vector);

 protected:
  // Propagate the values of the flags to the target modules.
  void PropagateParams() const;

  // @returns the space required to write the provided corrupt heap info.
  // @param corrupt_ranges The corrupt range info.
  size_t CalculateCorruptHeapInfoSize(
      const HeapChecker::CorruptRangesVector& corrupt_ranges);

  // Writes corrupt heap information to the provided buffer. This will write
  // as much of the information as possible in the space provided.
  // @param corrupt_ranges The corrupt range info.
  // @param buffer_size The size of the buffer to be written to. May be zero.
  // @param buffer The location where data will be written. May be null.
  // @param error_info The written heap metadata will be wired up to the
  //     provided error_info.
  void WriteCorruptHeapInfo(
      const HeapChecker::CorruptRangesVector& corrupt_ranges,
      size_t buffer_size,
      void* buffer,
      AsanErrorInfo* error_info);

  // Logs information about an ASAN error.
  void LogAsanErrorInfo(AsanErrorInfo* error_info);

 private:
  // Set up the logger.
  void SetUpLogger();

  // Tear down the logger.
  void TearDownLogger();

  // Set up the stack cache.
  void SetUpStackCache();

  // Tear down the stack cache.
  void TearDownStackCache();

  // The unhandled exception filter registered by this runtime. This is used
  // to catch unhandled exceptions so we can augment them with information
  // about the corrupt heap.
  static LONG WINAPI UnhandledExceptionFilter(
      struct _EXCEPTION_POINTERS* exception);

  // @name Static variables related to unhandled exception filtering (UEF).
  // @{
  static base::Lock lock_;  // Lock for all runtimes.
  static AsanRuntime* runtime_;  // Singleton. Under lock_.
  static LPTOP_LEVEL_EXCEPTION_FILTER previous_uef_;  // Under lock_.
  static bool uef_installed_;  // Under lock_.
  // @}

  // The shared logger instance that will be used by all heap proxies.
  scoped_ptr<AsanLogger> logger_;

  // The shared stack cache instance that will be used by all heap proxies.
  scoped_ptr<StackCaptureCache> stack_cache_;

  // The asan error callback functor.
  AsanOnErrorCallBack asan_error_callback_;

  // The heap proxies list lock.
  base::Lock heap_proxy_dlist_lock_;

  // The heap proxies list.
  LIST_ENTRY heap_proxy_dlist_;  // Under heap_proxy_dlist_lock.

  // The runtime parameters.
  common::InflatedAsanParameters params_;

  DISALLOW_COPY_AND_ASSIGN(AsanRuntime);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_RUNTIME_H_
