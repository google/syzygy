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

#include <memory>

#include "base/bind.h"
#include "base/synchronization/waitable_event.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

class DeferredFreeThreadTest : public testing::Test {
 public:
  DeferredFreeThreadTest() : nb_callbacks_(0), callback_event_(false, false) {}

  void SetUp() override {
    deferred_free_thread_.reset(new DeferredFreeThread(
        base::Bind(&DeferredFreeThreadTest::Callback, base::Unretained(this))));
    deferred_free_thread_->Start();
  }

  void TearDown() override {
    deferred_free_thread_->Stop();
    deferred_free_thread_.reset();
  }

  DeferredFreeThread* deferred_free_thread() {
    return deferred_free_thread_.get();
  }

  size_t nb_callbacks() {
    base::AutoLock auto_lock(nb_callbacks_lock_);
    return nb_callbacks_;
  }

  void Callback() {
    EXPECT_EQ(deferred_free_thread_->deferred_free_thread_id(),
              base::PlatformThread::CurrentId());
    base::AutoLock auto_lock(nb_callbacks_lock_);
    ++nb_callbacks_;
    callback_event_.Signal();
  }

  void WaitForCallback() { callback_event_.Wait(); }

 private:
  base::Lock nb_callbacks_lock_;
  size_t nb_callbacks_;
  std::unique_ptr<DeferredFreeThread> deferred_free_thread_;
  base::WaitableEvent callback_event_;
};

}  // namespace

TEST_F(DeferredFreeThreadTest, CallbackSignalingTest) {
  EXPECT_EQ(0, nb_callbacks());

  deferred_free_thread()->SignalWork();
  WaitForCallback();
  EXPECT_EQ(1, nb_callbacks());

  deferred_free_thread()->SignalWork();
  WaitForCallback();
  EXPECT_EQ(2, nb_callbacks());

  deferred_free_thread()->SignalWork();
  WaitForCallback();
  EXPECT_EQ(3, nb_callbacks());
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
