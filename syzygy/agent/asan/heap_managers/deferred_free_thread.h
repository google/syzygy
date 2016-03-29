// Copyright 2016 Google Inc. All Rights Reserved.
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
// Implementation of a background thread that that asynchronously trims the
// quarantine.

#ifndef SYZYGY_AGENT_ASAN_HEAP_MANAGERS_DEFERRED_FREE_THREAD_H_
#define SYZYGY_AGENT_ASAN_HEAP_MANAGERS_DEFERRED_FREE_THREAD_H_

#include "base/callback.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"

namespace agent {
namespace asan {
namespace heap_managers {

// This object can be created by each process. It spawns a low-priority
// background thread that is responsible for performing deferred work that
// Free() would otherwise be doing on the critical path. The goal is to improve
// responsiveness.
//
// As of now, this is responsible of trimming the shared quarantine. For more
// information on the trimming and the different modes and colors, see
// quarantine.h.
//
// Note that the thread must be cleanly shutdown by calling Stop before the
// HeapManager is cleaned up, otherwise the callback might still be running
// after the HeapManager no longer exists.
class DeferredFreeThread : public base::PlatformThread::Delegate {
 public:
  typedef base::Closure Callback;
  // @param deferred_free_callback Callback that is called by the thread when
  // signaled. This callback must be valid from the moment Start is called and
  // until Stop is called.
  explicit DeferredFreeThread(Callback deferred_free_callback);
  ~DeferredFreeThread() override;

  // Starts the thread and waits until it signals that it's ready to work. Must
  // be called before use. Must not be called if the thread has already been
  // started.
  // @returns true if successful, false if the thread failed to be launched.
  bool Start();

  // Stops the thread and waits until it exists cleanly. Must be called before
  // the destruction of this object and before the callback is no longer valid.
  // Must not be called if the thread has not been started previously.
  void Stop();

  // Used to signal to the thread that work is required (wakes up the thread).
  // It avoids over signaling (slow operation) by raising a flag
  // (|deferred_free_signaled_|) and bailing if it's already set (flag gets
  // unset by the thread). It's therefore ok to call this repeatedly.
  void SignalWork();

  // @returns the thread ID.
  base::PlatformThreadId deferred_free_thread_id() const {
    return deferred_free_thread_id_;
  }

 private:
  // Implementation of PlatformThread::Delegate:
  void ThreadMain() override;

  // Callback to the deferred free function, set by the constructor.
  Callback deferred_free_callback_;

  // Used to signal that work is ready (wakes up the background thread).
  base::WaitableEvent deferred_free_event_;
  // This atomic is set when the thread is signaled and cleared when the thread
  // wakes up. The objective is to limit the amount of over signaling possible.
  base::subtle::Atomic32 deferred_free_signaled_;

  // Handle to the thread, used to join the thread when stopping.
  base::PlatformThreadHandle deferred_free_thread_handle_;

  // The thread ID, can be used by callbacks to validate that they're running on
  // the right thread.
  base::PlatformThreadId deferred_free_thread_id_;

  // Used to signal that the background thread has spawned up and is ready to
  // work.
  base::WaitableEvent ready_event_;

  // Atomic that controls the execution of the background thread (loops while
  // this is true).
  base::subtle::Atomic32 enabled_;

  DISALLOW_COPY_AND_ASSIGN(DeferredFreeThread);
};

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_MANAGERS_DEFERRED_FREE_THREAD_H_
