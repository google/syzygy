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

#include "syzygy/trace/service/session.h"

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread.h"
#include "gtest/gtest.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/service_rpc_impl.h"
#include "syzygy/trace/service/session_trace_file_writer.h"
#include "syzygy/trace/service/session_trace_file_writer_factory.h"

namespace trace {
namespace service {

namespace {

class TestSessionTraceFileWriter : public SessionTraceFileWriter {
 public:
  explicit TestSessionTraceFileWriter(
      base::MessageLoop* message_loop, const base::FilePath& trace_directory)
      : SessionTraceFileWriter(message_loop, trace_directory),
        num_buffers_to_recycle_(0) {
    base::subtle::Barrier_AtomicIncrement(&num_instances_, 1);
  }

  ~TestSessionTraceFileWriter() {
    base::subtle::Barrier_AtomicIncrement(&num_instances_, -1);
  }

  void RecycleBuffers() {
    queue_lock_.AssertAcquired();

    while (!queue_.empty() && num_buffers_to_recycle_ != 0) {
      Buffer* buffer = queue_.front();
      queue_.pop_front();

      ASSERT_TRUE(buffer != NULL);
      ASSERT_EQ(buffer->session, session_ref_.get());
      ASSERT_TRUE(
        SessionTraceFileWriter::ConsumeBuffer(buffer));

      --num_buffers_to_recycle_;
    }

    // If we've emptied the queue, release our reference to the session.
    if (queue_.empty())
      session_ref_ = reinterpret_cast<Session*>(NULL);
  }

  void AllowBuffersToBeRecycled(size_t num_buffers) {
    base::AutoLock auto_lock(queue_lock_);

    num_buffers_to_recycle_ = num_buffers;
    RecycleBuffers();
  }

  virtual bool ConsumeBuffer(Buffer* buffer) OVERRIDE {
    base::AutoLock auto_lock(queue_lock_);
    EXPECT_TRUE(buffer != NULL);
    if (buffer) {
      // While there are buffers in the queue, keep a reference to the session.
      if (queue_.empty()) {
        EXPECT_TRUE(session_ref_.get() == NULL);
        EXPECT_TRUE(buffer->session != NULL);
        session_ref_ = buffer->session;
      }

      // Put the buffer into the consumer queue.
      queue_.push_back(buffer);
    }

    RecycleBuffers();

    return buffer != NULL;
  }

  static base::subtle::Atomic32 num_instances() {
    return base::subtle::Acquire_Load(&num_instances_);
  }

 protected:
  // The queue of buffers to be consumed.
  std::deque<Buffer*> queue_;

  // This keeps the session object alive while there are buffers in the queue.
  scoped_refptr<Session> session_ref_;

  // A lock to protect access to the queue and session reference.
  base::Lock queue_lock_;

  // The number of buffers to recycle berfore pausing.
  size_t num_buffers_to_recycle_;

  // The number of active writer instances.
  // @note All accesses to this member should be via base/atomicops.h functions.
  static volatile base::subtle::Atomic32 num_instances_;
};

volatile base::subtle::Atomic32 TestSessionTraceFileWriter::num_instances_ = 0;

class TestSessionTraceFileWriterFactory : public SessionTraceFileWriterFactory {
 public:
  explicit TestSessionTraceFileWriterFactory(base::MessageLoop* message_loop)
      : SessionTraceFileWriterFactory(message_loop) {
  }

  bool CreateConsumer(scoped_refptr<BufferConsumer>* consumer) OVERRIDE {
    // w00t, somewhat bogus coverage ploy, at least will reuse the DCHECKS.
    EXPECT_TRUE(SessionTraceFileWriterFactory::CreateConsumer(consumer));
    EXPECT_TRUE((*consumer)->HasOneRef());

    *consumer = new TestSessionTraceFileWriter(
       message_loop_, trace_file_directory_);
    return true;
  }
};

class TestSession : public Session {
 public:
  explicit TestSession(Service* service)
      : Session(service),
        waiting_for_buffer_to_be_recycled_(&lock_),
        waiting_for_buffer_to_be_recycled_state_(false),
        destroying_singleton_buffer_(&lock_),
        destroying_singleton_buffer_state_(false),
        last_singleton_buffer_destroyed_(NULL),
        singleton_buffers_destroyed_(0),
        allocating_buffers_(&lock_),
        allocating_buffers_state_(false) {
  }

  void AllowBuffersToBeRecycled(size_t num_buffers) {
    static_cast<TestSessionTraceFileWriter*>(
        buffer_consumer())->AllowBuffersToBeRecycled(num_buffers);
  }

  void ClearWaitingForBufferToBeRecycledState() {
    base::AutoLock lock(lock_);
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  void PauseUntilWaitingForBufferToBeRecycled() {
    base::AutoLock lock(lock_);
    while (!waiting_for_buffer_to_be_recycled_state_)
      waiting_for_buffer_to_be_recycled_.Wait();
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  void ClearDestroyingSingletonBufferState() {
    base::AutoLock lock(lock_);
    destroying_singleton_buffer_state_ = false;
  }

  void PauseUntilDestroyingSingletonBuffer() {
    base::AutoLock lock(lock_);
    while (!destroying_singleton_buffer_state_)
      destroying_singleton_buffer_.Wait();
    destroying_singleton_buffer_state_ = true;
  }

  void ClearAllocatingBuffersState() {
    base::AutoLock lock(lock_);
    allocating_buffers_state_ = false;
  }

  void PauseUntilAllocatingBuffers() {
    base::AutoLock lock(lock_);
    while (!allocating_buffers_state_)
      allocating_buffers_.Wait();
    waiting_for_buffer_to_be_recycled_state_ = false;
  }

  size_t buffer_requests_waiting_for_recycle() {
    base::AutoLock lock(lock_);
    return buffer_requests_waiting_for_recycle_;
  }

  virtual void OnWaitingForBufferToBeRecycled() OVERRIDE {
    lock_.AssertAcquired();
    waiting_for_buffer_to_be_recycled_state_ = true;
    waiting_for_buffer_to_be_recycled_.Signal();
  }

  virtual void OnDestroySingletonBuffer(Buffer* buffer) OVERRIDE {
    lock_.AssertAcquired();
    last_singleton_buffer_destroyed_ = buffer;
    singleton_buffers_destroyed_++;
    destroying_singleton_buffer_state_ = true;
    destroying_singleton_buffer_.Signal();
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
    lock_.AssertAcquired();

    allocating_buffers_state_ = true;
    allocating_buffers_.Signal();

    // Forward this to the original implementation.
    return Session::AllocateBuffers(count, size);
  }

  // Under lock_.
  base::ConditionVariable waiting_for_buffer_to_be_recycled_;
  bool waiting_for_buffer_to_be_recycled_state_;

  // Under lock_.
  base::ConditionVariable destroying_singleton_buffer_;
  bool destroying_singleton_buffer_state_;
  Buffer* last_singleton_buffer_destroyed_;
  size_t singleton_buffers_destroyed_;

  // Under lock_.
  base::ConditionVariable allocating_buffers_;
  bool allocating_buffers_state_;
};

typedef scoped_refptr<TestSession> TestSessionPtr;

class TestService : public Service {
 public:
  explicit TestService(BufferConsumerFactory* factory)
      : Service(factory),
        process_id_(0xfafafa) {
  }

  TestSessionPtr CreateTestSession() {
    scoped_refptr<Session> session;
    if (!GetNewSession(++process_id_, &session))
      return NULL;

    return TestSessionPtr(static_cast<TestSession*>(session.get()));
  }

  size_t num_active_sessions() const { return num_active_sessions_; }

 protected:
  virtual Session* CreateSession() OVERRIDE {
    return new TestSession(this);
  }

 private:
  uint32 process_id_;  // Under lock_;
};

class SessionTest : public ::testing::Test {
 public:
  SessionTest()
      : consumer_thread_("session-test-consumer-thread"),
        consumer_thread_has_started_(
            consumer_thread_.StartWithOptions(
                base::Thread::Options(base::MessageLoop::TYPE_IO, 0))),
        session_trace_file_writer_factory_(consumer_thread_.message_loop()),
        call_trace_service_(&session_trace_file_writer_factory_),
        rpc_service_instance_manager_(&call_trace_service_),
        worker1_("Worker1"),
        worker2_("Worker2") {
  }

  virtual void SetUp() OVERRIDE {
    testing::Test::SetUp();

    ASSERT_TRUE(consumer_thread_has_started_);
    EXPECT_EQ(0, call_trace_service_.num_active_sessions());
    EXPECT_EQ(0, TestSessionTraceFileWriter::num_instances());

    // Setup the buffer management to make it easy to force buffer contention.
    call_trace_service_.set_num_incremental_buffers(2);
    call_trace_service_.set_buffer_size_in_bytes(8192);

    // Create a temporary directory for the call trace files.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(session_trace_file_writer_factory_.SetTraceFileDirectory(
        temp_dir_.path()));

    // We give the service instance a "unique" id so that it does not interfere
    // with any other instances or tests that might be concurrently active.
    std::string instance_id(base::StringPrintf("%d", ::GetCurrentProcessId()));
    call_trace_service_.set_instance_id(base::UTF8ToWide(instance_id));

    // The instance id needs to be in the environment to be picked up by the
    // client library. We prefix the existing environment variable, if any.
    scoped_ptr<base::Environment> env(base::Environment::Create());
    ASSERT_FALSE(env.get() == NULL);
    std::string env_var;
    env->GetVar(::kSyzygyRpcInstanceIdEnvVar, &env_var);
    env_var.insert(0, ";");
    env_var.insert(0, instance_id);
    ASSERT_TRUE(env->SetVar(::kSyzygyRpcInstanceIdEnvVar, env_var));

    // Start our worker threads so we can use them later.
    ASSERT_TRUE(worker1_.Start());
    ASSERT_TRUE(worker2_.Start());
  }

  virtual void TearDown() OVERRIDE {
    // Stop the worker threads.
    worker2_.Stop();
    worker1_.Stop();

    // Stop the call trace service.
    EXPECT_TRUE(call_trace_service_.Stop());
    EXPECT_FALSE(call_trace_service_.is_running());
    EXPECT_EQ(0, call_trace_service_.num_active_sessions());
    EXPECT_EQ(0, TestSessionTraceFileWriter::num_instances());
  }

 protected:
  // The thread on which the trace file writer will consumer buffers and a
  // helper variable whose initialization we use as a trigger to start the
  // thread (ensuring it's message_loop is created). These declarations MUST
  // remain in this order and preceed that of trace_file_writer_factory_;
  base::Thread consumer_thread_;
  bool consumer_thread_has_started_;

  // The call trace service related objects. These declarations MUST be in
  // this order.
  TestSessionTraceFileWriterFactory session_trace_file_writer_factory_;
  TestService call_trace_service_;
  RpcServiceInstanceManager rpc_service_instance_manager_;

  // The directory where trace file output will be written.
  base::ScopedTempDir temp_dir_;

  // A couple of worker threads where we can dispatch closures.
  base::Thread worker1_;
  base::Thread worker2_;
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
  ASSERT_TRUE(call_trace_service_.Start(true));

  TestSessionPtr session = call_trace_service_.CreateTestSession();
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
  session->AllowBuffersToBeRecycled(9999);
}

TEST_F(SessionTest, BackPressureWorks) {
  // Configure things so that back-pressure will be easily forced.
  call_trace_service_.set_max_buffers_pending_write(1);
  ASSERT_TRUE(call_trace_service_.Start(true));

  TestSessionPtr session = call_trace_service_.CreateTestSession();
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
  worker1_.message_loop()->PostTask(FROM_HERE, buffer_getter3);

  // Wait for the session to start applying back-pressure. This occurs when it
  // has indicated that it is waiting for a buffer to be written.
  session->PauseUntilWaitingForBufferToBeRecycled();

  // Allow a single buffer to be written.
  session->AllowBuffersToBeRecycled(1);

  // Wait for the buffer getter to complete.
  worker1_.Stop();

  // Ensure the buffer was a recycled forced wait.
  ASSERT_TRUE(result3);
  ASSERT_EQ(buffer1, buffer3);

  // Return the last buffer and allow everything to be written.
  ASSERT_TRUE(session->ReturnBuffer(buffer3));
  session->AllowBuffersToBeRecycled(9999);
}

TEST_F(SessionTest, BackPressureIsLimited) {
  // Configure things so that back-pressure will be easily forced.
  call_trace_service_.set_max_buffers_pending_write(1);
  ASSERT_TRUE(call_trace_service_.Start(true));

  TestSessionPtr session = call_trace_service_.CreateTestSession();
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
  Buffer* buffer3 = NULL;
  base::Closure buffer_getter3 = base::Bind(
      &GetNextBuffer, session, &buffer3, &result3);
  worker1_.message_loop()->PostTask(FROM_HERE, buffer_getter3);

  // Wait for the session to start applying back-pressure. This occurs when it
  // has indicated that it is waiting for a buffer to be written.
  session->PauseUntilWaitingForBufferToBeRecycled();

  // At this point, there should be only one getter applying back pressure.
  ASSERT_EQ(1u, session->buffer_requests_waiting_for_recycle());

  // Allocate yet another buffer on a new thread, this will force an allocation
  // which in turn will satisfy as many waits as there are buffers allocated.
  bool result4 = false;
  Buffer* buffer4 = NULL;
  base::Closure buffer_getter4 = base::Bind(
      &GetNextBuffer, session, &buffer4, &result4);
  worker2_.message_loop()->PostTask(FROM_HERE, buffer_getter4);

  // Similarly, wait for an allocation. The second buffer getter should cause
  // one to occur.
  session->PauseUntilAllocatingBuffers();

  // Allow a single buffer to be written.
  session->AllowBuffersToBeRecycled(1);

  // Wait for the buffer getters to complete.
  worker1_.Stop();
  worker2_.Stop();
  ASSERT_TRUE(result3);
  ASSERT_TRUE(result4);

  // We can't guarantee where the returned buffers come from (recycled or
  // not), just that they should be returned.
  ASSERT_TRUE(buffer3 != NULL);
  ASSERT_TRUE(buffer4 != NULL);

  // Return the last 2 buffers and allow everything to be written.
  ASSERT_TRUE(session->ReturnBuffer(buffer3));
  ASSERT_TRUE(session->ReturnBuffer(buffer4));
  session->AllowBuffersToBeRecycled(9999);
}

TEST_F(SessionTest, LargeBufferRequestAvoidsBackPressure) {
  // Configure things so that back-pressure will be easily forced.
  call_trace_service_.set_max_buffers_pending_write(1);
  ASSERT_TRUE(call_trace_service_.Start(true));

  TestSessionPtr session = call_trace_service_.CreateTestSession();
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

  // Ask for a big buffer. This should go through immediately and side-step the
  // usual buffer pool. Thus, it is not subject to back-pressure.
  Buffer* buffer3 = NULL;
  ASSERT_TRUE(session->GetBuffer(10 * 1024 * 1024, &buffer3));
  ASSERT_EQ(10u * 1024 * 1024, buffer3->mapping_size);
  ASSERT_EQ(10u * 1024 * 1024, buffer3->buffer_size);
  ASSERT_EQ(0u, buffer3->buffer_offset);

  // Return the buffer and allow them all to be recycled.
  ASSERT_TRUE(session->ReturnBuffer(buffer3));
  session->AllowBuffersToBeRecycled(9999);

  // Wait until the singleton buffer has been destroyed.
  session->PauseUntilDestroyingSingletonBuffer();
  ASSERT_EQ(1, session->singleton_buffers_destroyed_);
  ASSERT_EQ(buffer3, session->last_singleton_buffer_destroyed_);
}

}  // namespace service
}  // namespace trace
