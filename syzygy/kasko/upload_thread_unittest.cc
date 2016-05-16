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

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/lock.h"
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
  WaitableTimerMock()
      : unmatched_activations_(0),
        event_(false, false),
        timer_activated_(false, false) {}

  ~WaitableTimerMock() override { EXPECT_EQ(0, unmatched_activations_); }

  // WaitableTimer implementation
  void Start() override {
    base::AutoLock auto_lock(lock_);
    event_.Reset();
    ++unmatched_activations_;
    timer_activated_.Signal();
  }

  HANDLE GetHANDLE() override { return event_.handle(); }

  // Returns true if Start() has been called. Resets after Trigger() is invoked.
  bool IsActivated() { return timer_activated_.IsSignaled(); }

  // Signals the timer event. Call WaitForActivation() first.
  void Trigger() {
    {
      base::AutoLock auto_lock(lock_);
      EXPECT_EQ(0, unmatched_activations_);
      event_.Signal();
    }
  }

  // Blocks until the timer is activated. Each call to Start() releases one call
  // to WaitForActivation().
  void WaitForActivation() {
    {
      base::AutoLock auto_lock(lock_);
      --unmatched_activations_;
    }
    while (true) {
      {
        base::AutoLock auto_lock(lock_);
        if (unmatched_activations_ >= 0)
          return;
      }
      timer_activated_.Wait();
    }
  }

 private:
  int unmatched_activations_;
  base::WaitableEvent event_;
  base::WaitableEvent timer_activated_;
  base::Lock lock_;

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
                                     base::WrapUnique(timer_), uploader);
  }

  // Creates an UploadThread that shares the same exclusive path as |other|.
  TestInstance(const TestInstance& other, const base::Closure& uploader) {
    timer_ = new WaitableTimerMock();
    instance_ = UploadThread::Create(other.exclusive_path_dir_.path(),
                                     base::WrapUnique(timer_), uploader);
  }

  ~TestInstance() {}

  UploadThread* get() { return instance_.get(); }
  WaitableTimerMock* timer() { return timer_; }

 private:
  // The exclusive path.
  base::ScopedTempDir exclusive_path_dir_;
  std::unique_ptr<UploadThread> instance_;
  WaitableTimerMock* timer_;

  DISALLOW_COPY_AND_ASSIGN(TestInstance);
};

// Returns a mock uploader that signals |event|.
base::Closure MakeUploader(base::WaitableEvent* event) {
  return base::Bind(&base::WaitableEvent::Signal, base::Unretained(event));
}

// A mock uploader that signals |upload_started| and then blocks on
// |unblock_upload|.
void BlockingUpload(base::WaitableEvent* upload_started,
                    base::WaitableEvent* unblock_upload) {
  upload_started->Signal();
  unblock_upload->Wait();
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

  // UploadOneNowAsync triggers an upload without the timer trigger.
  instance.get()->UploadOneNowAsync();
  upload_event.Wait();

  // The timer is reset after handling an upload requested via
  // UploadOneNowAsync().
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

  // UploadOneNowAsync triggers an upload without the timer trigger.
  instance_1.get()->UploadOneNowAsync();
  upload_event_1.Wait();
  instance_1.timer()->WaitForActivation();

  instance_2.get()->UploadOneNowAsync();
  upload_event_1.Wait();
  instance_1.timer()->WaitForActivation();

  // Give a broken implementation a chance to do something unexpected.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(instance_2.timer()->IsActivated());
  EXPECT_FALSE(upload_event_2.IsSignaled());

  // Shut down the active thread. The 2nd thread should take over.
  instance_1.get()->Join();
  instance_2.timer()->WaitForActivation();
  instance_2.timer()->Trigger();
  upload_event_2.Wait();

  instance_2.timer()->WaitForActivation();
  instance_2.get()->UploadOneNowAsync();
  upload_event_2.Wait();
  instance_2.timer()->WaitForActivation();

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

  // Give a broken implementation a chance to do something unexpected.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(upload_event_2.IsSignaled());

  instance_2.timer()->Trigger();
  upload_event_2.Wait();

  // Give a broken implementation a chance to do something unexpected.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(upload_event_1.IsSignaled());

  instance_1.timer()->WaitForActivation();
  instance_2.timer()->WaitForActivation();

  instance_2.timer()->Trigger();
  upload_event_2.Wait();
  instance_2.timer()->WaitForActivation();

  instance_1.timer()->Trigger();
  upload_event_1.Wait();
  instance_1.timer()->WaitForActivation();

  instance_2.get()->UploadOneNowAsync();
  upload_event_2.Wait();
  instance_2.timer()->WaitForActivation();

  // Give a broken implementation a chance to do something unexpected.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(upload_event_1.IsSignaled());

  instance_1.get()->UploadOneNowAsync();
  upload_event_1.Wait();
  instance_1.timer()->WaitForActivation();

  // Give a broken implementation a chance to do something unexpected.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(upload_event_2.IsSignaled());

  instance_1.get()->Join();
  instance_2.get()->Join();
}

TEST(UploadThreadTest, JoinBlocksOnUploadCompletion) {
  base::Thread join_thread("join thread");

  base::WaitableEvent upload_started(false, false);
  base::WaitableEvent unblock_upload(false, false);
  base::WaitableEvent join_started(false, false);
  base::WaitableEvent join_completed(false, false);

  TestInstance instance(base::Bind(&BlockingUpload,
                                   base::Unretained(&upload_started),
                                   base::Unretained(&unblock_upload)));

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

  // Release the blocking upload.
  unblock_upload.Signal();
  // Implementation detail: the UploadThread will reset the timer before
  // checking the stop event.
  instance.timer()->WaitForActivation();
  join_completed.Wait();
}

TEST(UploadThreadTest, UploadOneNowAsyncGuarantees) {
  base::Thread join_thread("join thread");

  base::WaitableEvent upload_started(false, false);
  base::WaitableEvent unblock_upload(false, false);

  TestInstance instance(base::Bind(&BlockingUpload,
                                   base::Unretained(&upload_started),
                                   base::Unretained(&unblock_upload)));

  ASSERT_TRUE(instance.get());
  ASSERT_TRUE(instance.timer());

  // Basic case.
  instance.get()->Start();
  instance.timer()->WaitForActivation();
  instance.get()->UploadOneNowAsync();
  upload_started.Wait();
  unblock_upload.Signal();

  // If a request is received while an upload is in progress the request is
  // honored immediately after the previous upload completes.
  instance.timer()->WaitForActivation();
  instance.timer()->Trigger();
  upload_started.Wait();
  // The thread is now blocking on |unblock_upload|.
  // Request an upload.
  instance.get()->UploadOneNowAsync();
  // End the initial upload.
  unblock_upload.Signal();
  // Implementation detail: the timer will be reset before the pending upload
  // request is detected.
  instance.timer()->WaitForActivation();
  // Now the requested upload should take place.
  upload_started.Wait();
  unblock_upload.Signal();

  // If a request is received when another request is already pending (not yet
  // started) the second request is ignored.
  instance.timer()->WaitForActivation();
  instance.timer()->Trigger();
  upload_started.Wait();
  // The thread is now blocking on |unblock_upload|.
  // Request an upload.
  instance.get()->UploadOneNowAsync();
  // Request a second upload - this request should be a no-op.
  instance.get()->UploadOneNowAsync();
  // End the initial upload.
  unblock_upload.Signal();
  // Implementation detail: the timer will be reset before the pending upload
  // request is detected.
  instance.timer()->WaitForActivation();
  // Now the first requested upload should take place.
  upload_started.Wait();
  unblock_upload.Signal();
  instance.timer()->WaitForActivation();
  // A small wait to allow a broken implementation to handle the second request.
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(100));
  EXPECT_FALSE(upload_started.IsSignaled());

  // Any request received before Stop() is called will be honoured, even if it
  // has not started yet.
  // Trigger a scheduled upload.
  instance.timer()->Trigger();
  upload_started.Wait();
  // The scheduled upload is blocking.
  // Request an upload.
  instance.get()->UploadOneNowAsync();
  // The requested upload has not started yet. Invoke Stop() on the
  // UploadThread.
  instance.get()->Stop();
  // End the initial upload.
  unblock_upload.Signal();
  // Implementation detail: the timer will be reset before the pending upload
  // request is detected.
  instance.timer()->WaitForActivation();
  // Now the requested upload should take place, even though Stop() was called.
  upload_started.Wait();
  // If we get here, the second upload occurred. Now unblock it.
  unblock_upload.Signal();
  // Implementation detail: the timer will be reset before the stop request is
  // detected.
  instance.timer()->WaitForActivation();
  instance.get()->Join();
}

}  // namespace kasko
