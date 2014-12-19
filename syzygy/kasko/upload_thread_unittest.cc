// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/upload_thread.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/waitable_timer.h"

namespace kasko {

namespace {

// Implements a WaitableTimer that can be triggered by tests.
class WaitableTimerMock : public WaitableTimer {
 public:
  WaitableTimerMock() : event_(false, false), timer_activated_(true, false) {}

  ~WaitableTimerMock() override {}

  // WaitableTimer implementation
  void Start() override {
    timer_activated_.Signal();
  }
  HANDLE GetHANDLE() override { return event_.handle(); }

  // Returns true if Start() has been called. Resets after Trigger() is invoked.
  bool IsActivated() { return timer_activated_.IsSignaled(); }

  // Signals the timer event. Resets IsActivated() to false.
  void Trigger() {
    EXPECT_TRUE(timer_activated_.IsSignaled());
    timer_activated_.Reset();
    event_.Signal();
  }

  // Blocks until the timer is activated.
  void WaitForActivation() { timer_activated_.Wait(); }

 private:
  base::WaitableEvent event_;
  base::WaitableEvent timer_activated_;

  DISALLOW_COPY_AND_ASSIGN(WaitableTimerMock);
};

// Configures an UploadThread instance for testing.
class TestInstance {
 public:
  // Creates an UploadThread with a unique exclusive path.
  explicit TestInstance(const base::Closure& uploader) {
    exclusive_path_dir_.CreateUniqueTempDir();
    timer_ = new WaitableTimerMock();
    instance_ = UploadThread::Create(exclusive_path_dir_.path(),
                                     make_scoped_ptr(timer_), uploader);
  }

  // Creates an UploadThread that shares the same exclusive path as |other|.
  TestInstance(const TestInstance& other, const base::Closure& uploader) {
    timer_ = new WaitableTimerMock();
    instance_ = UploadThread::Create(other.exclusive_path_dir_.path(),
                                     make_scoped_ptr(timer_), uploader);
  }

  ~TestInstance() {}

  UploadThread* get() { return instance_.get(); }
  WaitableTimerMock* timer() { return timer_; }

 private:
  // The exclusive path.
  base::ScopedTempDir exclusive_path_dir_;
  scoped_ptr<UploadThread> instance_;
  WaitableTimerMock* timer_;

  DISALLOW_COPY_AND_ASSIGN(TestInstance);
};

// Returns a mock uploader that signals |event|.
base::Closure MakeUploader(base::WaitableEvent* event) {
  return base::Bind(&base::WaitableEvent::Signal, base::Unretained(event));
}

// A mock uploader that signals |upload_started| and then blocks on
// |stop_upload|.
void BlockingUpload(base::WaitableEvent* upload_started,
                    base::WaitableEvent* stop_upload) {
  upload_started->Signal();
  stop_upload->Wait();
}

// Signals |join_started|, invokes upload_thread->Join(), and then signals
// |join_completed|.
void DoJoin(UploadThread* upload_thread,
            base::WaitableEvent* join_started,
            base::WaitableEvent* join_completed) {
  join_started->Signal();
  upload_thread->Join();
  join_completed->Signal();
}

}  // namespace

TEST(UploadThreadTest, BasicTest) {
  base::WaitableEvent upload_event(false, false);
  TestInstance instance(MakeUploader(&upload_event));

  ASSERT_TRUE(instance.get());
  EXPECT_FALSE(instance.timer()->IsActivated());

  // Start the thread, and it will activate the timer.
  instance.get()->Start();
  instance.timer()->WaitForActivation();

  // No upload occurs til the timer goes off.
  EXPECT_FALSE(upload_event.IsSignaled());

  // When the timer goes off, an upload is recorded.
  instance.timer()->Trigger();
  upload_event.Wait();

  // The thread goes back to reactivate the timer.
  instance.timer()->WaitForActivation();

  // Triggering again causes another upload.
  instance.timer()->Trigger();
  upload_event.Wait();

  // The thread goes back to reactivate the timer.
  instance.timer()->WaitForActivation();

  // Stop and shut down the thread.
  instance.get()->Stop();
  instance.get()->Join();

  // No more uploads occurred.
  EXPECT_FALSE(upload_event.IsSignaled());
}

TEST(UploadThreadTest, OnlyOneActivates) {
  base::WaitableEvent upload_event_1(false, false);
  TestInstance instance_1(MakeUploader(&upload_event_1));

  ASSERT_TRUE(instance_1.get());
  ASSERT_TRUE(instance_1.timer());
  EXPECT_FALSE(instance_1.timer()->IsActivated());

  base::WaitableEvent upload_event_2(false, false);
  // Pass instance_1 to share the exclusive path.
  TestInstance instance_2(instance_1, MakeUploader(&upload_event_2));

  ASSERT_TRUE(instance_2.get());
  ASSERT_TRUE(instance_2.timer());
  EXPECT_FALSE(instance_2.timer()->IsActivated());

  // Start the threads.
  instance_1.get()->Start();
  instance_1.timer()->WaitForActivation();

  instance_2.get()->Start();
  // Give a broken implementation a chance to activate the timer.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(instance_2.timer()->IsActivated());

  instance_1.timer()->Trigger();
  upload_event_1.Wait();

  EXPECT_FALSE(upload_event_2.IsSignaled());
  EXPECT_FALSE(instance_2.timer()->IsActivated());

  instance_1.timer()->WaitForActivation();

  // Shut down the active thread.
  instance_1.get()->Join();

  instance_2.timer()->WaitForActivation();
  instance_2.timer()->Trigger();
  upload_event_2.Wait();

  instance_2.get()->Join();
}

TEST(UploadThreadTest, SimultaneousActivationOnSeparatePaths) {
  base::WaitableEvent upload_event_1(false, false);
  TestInstance instance_1(MakeUploader(&upload_event_1));

  ASSERT_TRUE(instance_1.get());
  ASSERT_TRUE(instance_1.timer());
  EXPECT_FALSE(instance_1.timer()->IsActivated());

  base::WaitableEvent upload_event_2(false, false);
  // Since we don't pass instance_1 here, the second instance will use a new
  // exclusive path.
  TestInstance instance_2(MakeUploader(&upload_event_2));

  ASSERT_TRUE(instance_2.get());
  ASSERT_TRUE(instance_2.timer());
  EXPECT_FALSE(instance_2.timer()->IsActivated());

  instance_1.get()->Start();
  instance_1.timer()->WaitForActivation();

  instance_2.get()->Start();
  instance_2.timer()->WaitForActivation();

  instance_1.timer()->Trigger();
  upload_event_1.Wait();

  instance_2.timer()->Trigger();
  upload_event_2.Wait();

  instance_1.timer()->WaitForActivation();
  instance_2.timer()->WaitForActivation();

  instance_2.timer()->Trigger();
  upload_event_2.Wait();

  instance_1.timer()->Trigger();
  upload_event_1.Wait();

  instance_1.get()->Join();
  instance_2.get()->Join();
}

TEST(UploadThreadTest, JoinBlocksOnUploadCompletion) {
  base::Thread join_thread("join thread");

  base::WaitableEvent upload_started(false, false);
  base::WaitableEvent stop_upload(false, false);
  base::WaitableEvent join_started(false, false);
  base::WaitableEvent join_completed(false, false);

  TestInstance instance(base::Bind(&BlockingUpload,
                                   base::Unretained(&upload_started),
                                   base::Unretained(&stop_upload)));

  ASSERT_TRUE(instance.get());
  ASSERT_TRUE(instance.timer());

  instance.get()->Start();
  instance.timer()->WaitForActivation();
  instance.timer()->Trigger();
  upload_started.Wait();
  EXPECT_TRUE(join_thread.Start());
  join_thread.message_loop()->PostTask(FROM_HERE, base::Bind(
      &DoJoin, base::Unretained(instance.get()),
      base::Unretained(&join_started), base::Unretained(&join_completed)));
  join_started.Wait();

  // A small wait to allow a chance for a broken Join to return early.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  stop_upload.Signal();
  join_completed.Wait();
}

}  // namespace kasko
