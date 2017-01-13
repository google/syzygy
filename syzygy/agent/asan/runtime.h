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

#ifndef SYZYGY_AGENT_ASAN_RUNTIME_H_
#define SYZYGY_AGENT_ASAN_RUNTIME_H_

#include <memory>
#include <set>
#include <string>

#include "base/callback.h"
#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/heap_checker.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/agent/asan/reporter.h"
#include "syzygy/agent/asan/heap_managers/block_heap_manager.h"
#include "syzygy/agent/common/stack_capture.h"
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
  typedef std::set<common::StackCapture::StackId> StackIdSet;

  // The type of callback used by the OnError function.
  typedef base::Callback<void(AsanErrorInfo*)> AsanOnErrorCallBack;

  AsanRuntime();
  ~AsanRuntime();

  // @name Accessors.
  // @{
  MemoryNotifierInterface* memory_notifier() const {
    return memory_notifier_.get();
  }
  AsanLogger* logger() const { return logger_.get(); }
  Shadow* shadow() const { return shadow_.get(); }
  StackCaptureCache* stack_cache() const { return stack_cache_.get(); }
  ReporterInterface* crash_reporter() const { return crash_reporter_.get(); }
  // @}

  // Initialize asan runtime library.
  // @param flags_command_line The parameters string.
  // @returns true on success, false otherwise.
  bool SetUp(const std::wstring& flags_command_line);

  // Release asan runtime library.
  void TearDown();

  // The body of the OnError functions, minus the error handler callback.
  // Factored out for reuse by OnError and unfiltered exception handling.
  // @param error_info The information about this error.
  void OnErrorImpl(AsanErrorInfo* error_info);

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

  // Returns true if we should ignore the given @p stack_id, false
  // otherwise.
  bool ShouldIgnoreError(::common::AsanStackId stack_id) const {
    // TODO(sebmarchand): Keep a list of the stack ids that have already been
    //     reported so we can avoid reporting the same error multiple times.
    return params_.ignored_stack_ids_set.find(stack_id) !=
        params_.ignored_stack_ids_set.end();
  }

  // Get information about a bad access.
  // @param bad_access_info Will receive the information about this access.
  void GetBadAccessInformation(AsanErrorInfo* error_info);

  // TODO(chrisha): Make this a proper singleton.
  // @returns the singleton runtime.
  static AsanRuntime* runtime() { return runtime_; }

  // Accessors for runtime parameters.
  ::common::InflatedAsanParameters& params() { return params_; }
  const ::common::InflatedAsanParameters& params() const { return params_; }

  // @returns the value of the tick counter when the runtime was created.
  uint32_t starting_ticks() const { return starting_ticks_; }

  // Retrieves the process's heap.
  // @returns The ID of the process's heap.
  HeapManagerInterface::HeapId GetProcessHeap() {
    return heap_manager_->process_heap();
  }

  // Returns the allocation-filter flag value.
  // @returns the allocation-filter flag value.
  // @note The flag is stored per-thread using TLS. Multiple threads do not
  //     share the same flag.
  bool allocation_filter_flag();

  // Sets the allocation-filter flag to the specified value.
  // @param value the new value for the flag.
  // @note The flag is stored per-thread using TLS. Multiple threads do not
  //     share the same flag.
  void set_allocation_filter_flag(bool value);

  // @names Accessors.
  // {
  uint64_t random_key() const { return random_key_; }
  bool crash_reporter_initialized() const {
    return crash_reporter_initialized_;
  }
  // @}

  // Observes a given thread ID, adding it to thread ID set.
  // @param thread_id The thread ID that has been observed.
  void AddThreadId(uint32_t thread_id);

  // Determines if a thread ID has already been seen.
  // @param thread_id The thread ID to be queried.
  // @returns true if a given thread ID is valid for this process.
  bool ThreadIdIsValid(uint32_t thread_id);

  // @name Introspection entry points into the block heap manager. These
  //    are only meant to be run when the block heap manager lock is already
  //    held, like during crash processing. If used in unittests care must be
  //    taken to ensure the access is synchronous if the lock isn't otherwise
  //    held.
  // @{
  // Determines if a given heap ID is valid.
  // @param uint32_t heap_id The heap ID to check.
  // @returns true if valid, false otherwise.
  bool HeapIdIsValid(HeapManagerInterface::HeapId heap_id);

  // Returns the type of a given heap.
  // @param uint32_t heap_id The heap ID to check.
  // @returns the heap type, or kUnknownHeapType if the heap is invalid.
  HeapType GetHeapType(HeapManagerInterface::HeapId heap_id);
  // @}

  // Processes an exception and determines if an Asan error has occurred,
  // updating the exception if so. If Breakpad is enabled, passes the
  // exception to it, otherwise lets the exception continue unhandled.
  // @note This is basically a Windows SEH exception filter.
  // @param exception The exception to be processed.
  // @returns EXCEPTION_CONTINUE_SEARCH or EXCEPTION_EXECUTE_HANDLER.
  static int CrashForException(EXCEPTION_POINTERS* exception);

  // Enables the deferred free thread.
  void EnableDeferredFreeThread();

  // Disables the deferred free thread.
  void DisableDeferredFreeThread();

  // @returns the list of enabled features.
  AsanFeatureSet GetEnabledFeatureSet();

  // Initialize the crash reporter used by the runtime.
  //
  // This function should only be called once during the runtime's lifetime,
  // it could either be called at setup time if the deferred initialization
  // flag hasn't been set on the command line or later by the instrumented
  // image.
  //
  // Calling this when the crash reporter has already been initialized will
  // terminate the process.
  void InitializeCrashReporter();

 protected:
  // Propagate the values of the flags to the target modules.
  void PropagateParams();

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

  // Logs information about an Asan error.
  void LogAsanErrorInfo(AsanErrorInfo* error_info);

  // @returns a value describing the state of the features that can be randomly
  //     enabled or disabled.
  static AsanFeatureSet GenerateRandomFeatureSet();

  // Randomly enable some features.
  // @param feature_set The feature set indicating the features to update.
  void PropagateFeatureSet(AsanFeatureSet feature_set);

  // The heap manager.
  std::unique_ptr<heap_managers::BlockHeapManager>
      heap_manager_;  // Under lock_.

 private:
  // Sets up the shadow memory.
  // @returns true on success, false otherwise.
  bool SetUpShadow();

  // Tears down the shadow memory.
  void TearDownShadow();

  // Set up the memory notifier.
  // @returns true on success, false otherwise.
  bool SetUpMemoryNotifier();

  // Tear down the memory notifier.
  void TearDownMemoryNotifier();

  // Set up the logger.
  // @returns true on success, false otherwise.
  bool SetUpLogger();

  // Tear down the logger.
  void TearDownLogger();

  // Set up the stack cache.
  // @returns true on success, false otherwise.
  bool SetUpStackCache();

  // Tear down the stack cache.
  void TearDownStackCache();

  // Set up the heap manager.
  // @returns true on success, false otherwise.
  bool SetUpHeapManager();

  // Tear down the heap manager.
  void TearDownHeapManager();

  // The unhandled exception filter registered by this runtime. This is used
  // to catch unhandled exceptions so we can augment them with information
  // about the corrupt heap.
  static LONG WINAPI UnhandledExceptionFilter(
      struct _EXCEPTION_POINTERS* exception);

  // The implementation of the Asan exception handler. This has two flavours:
  // in the context of an unhandled exception filter, and in the context of
  // an exception handler. If |is_unhandled| is true then this will pass the
  // exception along to the next unfiltered exception handler. Otherwise, it'll
  // pass it along to Breakpad, if present. Finally, it'll let the exception
  // processing continue unhandled.
  static LONG ExceptionFilterImpl(bool is_unhandled,
                                  EXCEPTION_POINTERS* exception);

  // @name Static variables related to unhandled exception filtering (UEF).
  // @{
  static base::Lock lock_;  // Lock for all runtimes.
  static AsanRuntime* runtime_;  // Singleton. Under lock_.
  static LPTOP_LEVEL_EXCEPTION_FILTER previous_uef_;  // Under lock_.
  static bool uef_installed_;  // Under lock_.
  // @}

  // The shadow memory used by this runtime.
  std::unique_ptr<Shadow> shadow_;

  // The shared memory notifier that will be used to update the shadow memory
  // with redzones for internally allocated memory.
  std::unique_ptr<MemoryNotifierInterface> memory_notifier_;

  // The shared logger instance that will be used to report errors and runtime
  // information.
  std::unique_ptr<AsanLogger> logger_;

  // The shared stack cache instance that will be used by all the heaps.
  std::unique_ptr<StackCaptureCache> stack_cache_;

  // The asan error callback functor.
  AsanOnErrorCallBack asan_error_callback_;

  // The runtime parameters.
  ::common::InflatedAsanParameters params_;

  // The tick counter when the runtime was created. This is used for
  // bracketing valid alloc and free ticks values.
  uint32_t starting_ticks_;

  // The set of thread IDs that have been seen in the current process.
  // This is used to validate thread IDs in a block trailer.
  base::Lock thread_ids_lock_;
  std::unordered_set<uint32_t> thread_ids_;  // Under thread_ids_lock_.

  // A random key that is generated on object creation. This is used for
  // correlating duplicate crash reports on the back-end.
  const uint64_t random_key_;

  // The crash reporter in use. This will be left null if no crash reporter
  // is available.
  std::unique_ptr<ReporterInterface> crash_reporter_;

  // Indicates if the crash reporter has been initialized.
  bool crash_reporter_initialized_;

  DISALLOW_COPY_AND_ASSIGN(AsanRuntime);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_RUNTIME_H_
