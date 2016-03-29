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

#include "syzygy/agent/asan/heap_managers/deferred_free_thread.h"

namespace agent {
namespace asan {
namespace heap_managers {

DeferredFreeThread::DeferredFreeThread(Callback deferred_free_callback)
    : deferred_free_callback_(deferred_free_callback),
      deferred_free_event_(false, false),
      deferred_free_signaled_(0),
      ready_event_(false, false),
      enabled_(0) {
}

DeferredFreeThread::~DeferredFreeThread() {
  DCHECK_EQ(0, base::subtle::NoBarrier_Load(&enabled_));
}

bool DeferredFreeThread::Start() {
  auto old_enabled = base::subtle::NoBarrier_AtomicExchange(&enabled_, 1);
  DCHECK_EQ(0, old_enabled);
  // Make sure the change to |enabled_| is not reordered.
  base::subtle::MemoryBarrier();
  if (!base::PlatformThread::CreateWithPriority(
          0, this, &deferred_free_thread_handle_,
          base::ThreadPriority::BACKGROUND)) {
    return false;
  }
  ready_event_.Wait();
  return true;
}

void DeferredFreeThread::Stop() {
  auto old_enabled = base::subtle::NoBarrier_AtomicExchange(&enabled_, 0);
  DCHECK_EQ(1, old_enabled);
  // Make sure the change to |enabled_| is not reordered.
  base::subtle::MemoryBarrier();
  // Signal so that the thread can exit cleanly and then join it.
  deferred_free_event_.Signal();
  base::PlatformThread::Join(deferred_free_thread_handle_);
}

void DeferredFreeThread::SignalWork() {
  // Avoid over signaling by trying to raise the |deferred_free_signaled_| flag
  // and bailing if the flag was already raised.
  auto initial_deferred_free_signaled =
      base::subtle::NoBarrier_CompareAndSwap(&deferred_free_signaled_, 0, 1);
  if (initial_deferred_free_signaled)
    return;

  deferred_free_event_.Signal();
}

void DeferredFreeThread::ThreadMain() {
  base::PlatformThread::SetName("SyzyASAN Deferred Free Thread");
  deferred_free_thread_id_ = base::PlatformThread::CurrentId();
  ready_event_.Signal();
  while (true) {
    deferred_free_event_.Wait();
    if (!base::subtle::NoBarrier_Load(&enabled_))
      break;
    // Clear the |deferred_free_signaled_| flag before executing the callback.
    auto initial_deferred_free_signaled =
        base::subtle::NoBarrier_CompareAndSwap(&deferred_free_signaled_, 1, 0);
    DCHECK(initial_deferred_free_signaled);
    deferred_free_callback_.Run();
  }
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
