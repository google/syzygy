// Copyright 2012 Google Inc.
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

#include "syzygy/trace/service/session.h"

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/file_util.h"
#include "base/threading/thread.h"
#include "gtest/gtest.h"
#include "syzygy/trace/service/service.h"

namespace trace {
namespace service {

namespace {

class TestSession : public Session {
 public:
  explicit TestSession(Service* service, base::Lock* lock)
      : Session(service),
        test_lock_(lock),
        waiting_for_buffer_to_be_recycled_(lock),
        waiting_for_buffer_to_be_recycled_state_(false),
        allocating_buffers_(lock),
        allocating_buffers_state_(false) {
    base::subtle::Barrier_AtomicIncrement(&instance_count_, 1);
  }

  ~TestSession() {
    base::subtle::Barrier_AtomicIncrement(&instance_count_, -1);
  }

  static base::subtle::Atomic32 instance_count() {
    return instance_count_;
  }

  void ClearWaitingForBufferToBeRecycledState() {
    base::AutoLock lock(*test_lock_);
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  void PauseUntilWaitingForBufferToBeRecycled() {
    base::AutoLock lock(*test_lock_);
    while (!waiting_for_buffer_to_be_recycled_state_)
      waiting_for_buffer_to_be_recycled_.Wait();
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  void ClearAllocatingBuffersState() {
    base::AutoLock lock(*test_lock_);
    allocating_buffers_state_ = false;
  }

  void PauseUntilAllocatingBuffers() {
    base::AutoLock lock(*test_lock_);
    while (!allocating_buffers_state_)
      allocating_buffers_.Wait();
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  size_t buffer_requests_waiting_for_recycle() {
    base::AutoLock lock(*test_lock_);
    return buffer_requests_waiting_for_recycle_;
  }

 protected:
  virtual void OnWaitingForBufferToBeRecycled() OVERRIDE {
    base::AutoLock lock(*test_lock_);
    waiting_for_buffer_to_be_recycled_state_ = true;
    waiting_for_buffer_to_be_recycled_.Signal();
  }

  bool InitializeProcessInfo(ProcessId process_id,
                             ProcessInfo* client) OVERRIDE {
    DCHECK(client != NULL);

    // Lobotomize the process info initialization to allow using fake PIDs.
    client->process_id = process_id;
    const DWORD kFlags =
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    client->process_handle.Set(
        ::OpenProcess(kFlags, FALSE, ::GetCurrentProcessId()));
    static const wchar_t kEnvironment[] = L"asdf=fofofo\0";
    client->environment.assign(kEnvironment,
                               kEnvironment + arraysize(kEnvironment));

    return true;
  }

  bool CopyBufferHandleToClient(HANDLE client_process_handle,
                                HANDLE local_handle,
                                HANDLE* client_copy) OVERRIDE {
    // Avoid handle leaks by using the same handle for both "ends".
    *client_copy = local_handle;
    return true;
  }

  virtual bool AllocateBuffers(size_t count, size_t size) OVERRIDE {
    {
      base::AutoLock lock(*test_lock_);
      allocating_buffers_state_ = true;
      allocating_buffers_.Signal();
    }

    // Forward this to the original implementation.
    return Session::AllocateBuffers(count, size);
  }

 private:
  base::Lock* test_lock_;

  // Under test_lock_.
  base::ConditionVariable waiting_for_buffer_to_be_recycled_;
  bool waiting_for_buffer_to_be_recycled_state_;

  // Under test_lock_.
  base::ConditionVariable allocating_buffers_;
  bool allocating_buffers_state_;

  // Updated atomically.
  static base::subtle::Atomic32 instance_count_;
};

base::subtle::Atomic32 TestSession::instance_count_ = 0;

typedef scoped_refptr<TestSession> TestSessionPtr;

class TestService : public Service {
 public:
  TestService()
      : process_id_(0xfafafa),
        buffers_written_(&buffers_written_lock_),
        buffers_allowed_to_be_recycled_(0) {
  }

  TestSessionPtr CreateTestSession() {
    base::AutoLock lock(lock_);

    scoped_refptr<Session> session;
    if (!GetNewSession(++process_id_, &session))
      return NULL;

    return TestSessionPtr(reinterpret_cast<TestSession*>(session.get()));
  }

  void WaitUntilAllowedBuffersWritten() {
    base::AutoLock lock(buffers_written_lock_);
    while (buffers_allowed_to_be_recycled_ > 0)
      buffers_written_.Wait();
  }

  void AllowBuffersToBeRecycled(size_t count) {
    base::AutoLock lock(queue_lock_);
    buffers_allowed_to_be_recycled_ += count;
  }

 protected:
  virtual Session* CreateSession() OVERRIDE {
    return new TestSession(this, &session_lock_);
  }

  virtual bool GetBuffersToWrite(BufferQueue* queue) OVERRIDE {
    DCHECK(queue != NULL);
    DCHECK(queue->empty());

    base::AutoLock qlock(queue_lock_);
    base::AutoLock bwlock(buffers_written_lock_);

    if (buffers_allowed_to_be_recycled_ == 0)
      return true;

    while (pending_write_queue_.empty())
      queue_is_non_empty_.Wait();

    // Pop out some buffers, but not too many.
    while (!pending_write_queue_.empty() && buffers_allowed_to_be_recycled_) {
      queue->push_back(pending_write_queue_.front());
      pending_write_queue_.pop_front();
      --buffers_allowed_to_be_recycled_;
    }

    buffers_written_.Signal();

    return true;
  };

 private:
  // This lock is provided to sessions for misc locking.
  base::Lock session_lock_;

  uint32 process_id_;  // Under lock_;

  base::Lock buffers_written_lock_;
  base::ConditionVariable buffers_written_;  // Under buffers_written_lock_.
  size_t buffers_allowed_to_be_recycled_;  // Under buffers_written_lock_.
};

class SessionTest : public ::testing::Test {
 public:
  SessionTest() : worker1("Worker1"), worker2("Worker2") {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", &temp_dir_));
    service_.set_trace_directory(temp_dir_);
    worker1.Start();
    worker2.Start();
  }

  virtual void TearDown() OVERRIDE {
    worker1.Stop();
    worker2.Stop();
    service_.Stop();
    EXPECT_EQ(0, TestSession::instance_count());
    file_util::Delete(temp_dir_, true);
  }

  FilePath temp_dir_;
  TestService service_;

  // A couple of worker threads where we can dispatch closures.
  base::Thread worker1;
  base::Thread worker2;
};

void GetNextBuffer(Session* session, Buffer** buffer, bool* result) {
  DCHECK(session != NULL);
  DCHECK(buffer != NULL);
  DCHECK(result != NULL);
  *buffer = NULL;
  *result = session->GetNextBuffer(buffer);
}

}  // namespace

TEST_F(SessionTest, ReturnBufferWorksAfterSessionClose) {
  ASSERT_TRUE(service_.Start(true));

  TestSessionPtr session = service_.CreateTestSession();
  ASSERT_TRUE(session != NULL);

  Buffer* buffer1 = NULL;
  ASSERT_TRUE(session->GetNextBuffer(&buffer1));
  ASSERT_TRUE(buffer1 != NULL);

  ASSERT_TRUE(session->Close());

  // Closing the session should have forced all buffers to be submitted to
  // the write queue.
  ASSERT_EQ(Buffer::kPendingWrite, buffer1->state);

  // A request for another buffer should fail.
  Buffer* buffer2 = NULL;
  ASSERT_FALSE(session->GetNextBuffer(&buffer2));
  ASSERT_TRUE(buffer2 == NULL);

  // Returning the original buffer should be a noop, but it should succeed.
  // Most of all, it shouldn't cause a race condition.
  ASSERT_TRUE(session->ReturnBuffer(buffer1));

  // Let's allow the outstanding buffers to be written.
  service_.AllowBuffersToBeRecycled(9999);

  ASSERT_TRUE(service_.Stop());
}

TEST_F(SessionTest, BackPressureWorks) {
  // Configure things so that back-pressure will be easily forced.
  service_.set_num_incremental_buffers(2);
  service_.set_buffer_size_in_bytes(1024);
  service_.set_max_buffers_pending_write(1);
  ASSERT_TRUE(service_.Start(true));

  TestSessionPtr session = service_.CreateTestSession();
  ASSERT_TRUE(session != NULL);

  Buffer* buffer1 = NULL;
  ASSERT_TRUE(session->GetNextBuffer(&buffer1));
  ASSERT_TRUE(buffer1 != NULL);

  Buffer* buffer2 = NULL;
  ASSERT_TRUE(session->GetNextBuffer(&buffer2));
  ASSERT_TRUE(buffer2 != NULL);

  // Return both buffers so we have 2 pending writes. Neither of these will
  // go through because we have not allowed any buffers to be written yet.
  ASSERT_TRUE(session->ReturnBuffer(buffer1));
  ASSERT_TRUE(session->ReturnBuffer(buffer2));

  // We don't care about events up until this point.
  session->ClearWaitingForBufferToBeRecycledState();

  // Start the buffer getter. This launches another thread that will try to
  // get another buffer. This will be blocked because of the pending writes.
  bool result3 = false;
  Buffer* buffer3 = NULL;
  base::Closure buffer_getter3 = base::Bind(
      &GetNextBuffer, session, &buffer3, &result3);
  worker1.message_loop()->PostTask(FROM_HERE, buffer_getter3);

  // Wait for the session to start applying back-pressure. This occurs when it
  // has indicated that it is waiting for a buffer to be written.
  session->PauseUntilWaitingForBufferToBeRecycled();

  // Allow a single buffer to be written.
  service_.AllowBuffersToBeRecycled(1);

  // Wait for the buffer getter to complete.
  worker1.Stop();

  // Ensure the buffer was a recycled forced wait.
  ASSERT_TRUE(result3);
  ASSERT_EQ(buffer1, buffer3);

  // Return the last buffer and allow everything to be written.
  ASSERT_TRUE(session->ReturnBuffer(buffer3));
  service_.AllowBuffersToBeRecycled(9999);

  ASSERT_TRUE(service_.Stop());
}

TEST_F(SessionTest, BackPressureIsLimited) {
  // Configure things so that back-pressure will be easily forced.
  service_.set_num_incremental_buffers(2);
  service_.set_buffer_size_in_bytes(1024);
  service_.set_max_buffers_pending_write(1);
  ASSERT_TRUE(service_.Start(true));

  TestSessionPtr session = service_.CreateTestSession();
  ASSERT_TRUE(session != NULL);

  Buffer* buffer1 = NULL;
  ASSERT_TRUE(session->GetNextBuffer(&buffer1));
  ASSERT_TRUE(buffer1 != NULL);

  Buffer* buffer2 = NULL;
  ASSERT_TRUE(session->GetNextBuffer(&buffer2));
  ASSERT_TRUE(buffer2 != NULL);

  // Return both buffers so we have 2 pending writes. Neither of these will
  // go through because we have not allowed any buffers to be written yet.
  ASSERT_TRUE(session->ReturnBuffer(buffer1));
  ASSERT_TRUE(session->ReturnBuffer(buffer2));

  // Since the back-pressure threshold is 1 and we have 2 pending buffers
  // if 1 is recycled it will bring us below the back-pressure threshold. Thus
  // if we pile on a lot of buffer requests, only the first one should apply
  // back-pressure, and the next ones should cause an allocation.

  // We don't care about events up until this point.
  session->ClearWaitingForBufferToBeRecycledState();
  session->ClearAllocatingBuffersState();

  bool result3 = false;
  bool result4 = false;
  Buffer* buffer3 = NULL;
  Buffer* buffer4 = NULL;
  base::Closure buffer_getter3 = base::Bind(
      &GetNextBuffer, session, &buffer3, &result3);
  base::Closure buffer_getter4 = base::Bind(
      &GetNextBuffer, session, &buffer4, &result4);
  worker1.message_loop()->PostTask(FROM_HERE, buffer_getter3);
  worker2.message_loop()->PostTask(FROM_HERE, buffer_getter4);

  // Wait for the session to start applying back-pressure. This occurs when it
  // has indicated that it is waiting for a buffer to be written.
  session->PauseUntilWaitingForBufferToBeRecycled();

  // Similarly, wait for an allocation. The second buffer getter should cause
  // one to occur.
  session->PauseUntilAllocatingBuffers();

  // At this point, there should be only one getter applying back pressure.
  ASSERT_EQ(1u, session->buffer_requests_waiting_for_recycle());

  // Allow a single buffer to be written.
  service_.AllowBuffersToBeRecycled(1);

  // Wait for the buffer getters to complete.
  worker1.Stop();
  worker2.Stop();
  ASSERT_TRUE(result3);
  ASSERT_TRUE(result4);

  // We can't guarantee where the returned buffers come from (recycled or
  // not), just that they should be returned.
  ASSERT_TRUE(buffer3 != NULL);
  ASSERT_TRUE(buffer4 != NULL);

  // Return the last 2 buffers and allow everything to be written.
  ASSERT_TRUE(session->ReturnBuffer(buffer3));
  ASSERT_TRUE(session->ReturnBuffer(buffer4));
  service_.AllowBuffersToBeRecycled(9999);

  ASSERT_TRUE(service_.Stop());
}

}  // namespace trace
}  // namespace service
