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
//
// This file declares the trace::service::Service class which implements
// the call trace service RPC interface.

#ifndef SYZYGY_TRACE_SERVICE_SERVICE_H_
#define SYZYGY_TRACE_SERVICE_SERVICE_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/process.h"
#include "base/string_piece.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "syzygy/trace/service/session.h"

namespace trace {
namespace service {

// Implements the CallTraceService interface (see "call_trace_rpc.idl".
// For the most basic usage:
//
//   trace::service::Service::Instance().Start(false);
//
// This will access and launch a static instance of the service using a
// default configuration. Specifying false, as in the above example,
// will cause the call to be blocking; the call will not return until
// the service is shutdown via the RequestShutdown() method. Specifying
// true for the parameter to Start() will cause the Start() method to
// return immediately, running the service in the background.
//
// Some mechanism to trigger a call to RequestShutdown() should be
// provided to the operator of the service; for example, a signal handler
// on SIGINT and/or SIGTERM, an event listening listening for a shutdown
// Message, an IO loop waiting on a socket or Event, etc. The service
// can also stopped remotely via an RPC call to CallTraceControl::Stop().
class Service : public base::PlatformThread::Delegate {
 public:
  typedef base::ProcessId ProcessId;

  // Flag passed to CommitAndExchangeBuffer() to determine whether or
  // not a fresh buffer should be returned to the client.
  enum ExchangeFlag {
    DO_NOT_PERFORM_EXCHANGE,
    PERFORM_EXCHANGE
  };

  Service();
  ~Service();

  // Accessor for a static/singleton instance of the Service.
  static Service& Instance();

  // The default number of buffers to allocate when expanding the buffer
  // pool allocated for a given client session.
  static const size_t kDefaultNumIncrementalBuffers;

  // The default size (in bytes) for each call trace buffer.
  static const size_t kDefaultBufferSize;

  // The default maximum number of buffers pending write that a session should
  // allow before beginning to force writes.
  static const size_t kDefaultMaxBuffersPendingWrite;

  // Set the id for this instance.
  void set_instance_id(const base::StringPiece16& id) {
    DCHECK(!is_running());
    instance_id_.assign(id.begin(), id.end());
  }

  // Set the trace flags that get communicated to clients on session creation.
  // The flags value should be bitmask composed of the values from the
  // TraceEventType enumeration (see call_trace_defs.h).
  //
  // @note TRACE_FLAG_BATCH_ENTER is mutually exclusive with all other flags.
  //     If TRACE_FLAG_BATCH_ENTER is set, all other flags will be ignored.
  void set_flags(uint32 flags) {
    flags_ = flags;
  }

  // Set the directory where trace files are stored.
  void set_trace_directory(const FilePath& directory) {
    DCHECK(!directory.empty());
    trace_directory_ = directory;
  }

  // Set the number of buffers by which to grow a sessions
  // buffer pool.
  void set_num_incremental_buffers(size_t n) {
    num_incremental_buffers_ = n;
  }

  // Set the number of bytes comprising each buffer in a
  // sessions buffer pool.
  void set_buffer_size_in_bytes(size_t n) {
    buffer_size_in_bytes_ = n;
  }

  // Sets the maximum number of buffers pending write that a session should
  // allow before starting to force buffer writes.
  // @param n the max number of buffers pending write to allow.
  void set_max_buffers_pending_write(size_t n) {
    DCHECK_LT(0u, n);
    max_buffers_pending_write_ = n;
  }

  // @returns the number of new buffers to be created per allocation.
  size_t num_incremental_buffers() const { return num_incremental_buffers_; }

  // @returns the size (in bytes) of new buffers to be allocated.
  size_t buffer_size_in_bytes() const { return buffer_size_in_bytes_; }

  // @returns the maximum number of buffers that sessions should allow to be
  //     pending writes prior to starting to force them.
  size_t max_buffers_pending_write() const {
    return max_buffers_pending_write_;
  }

  // Returns true if any of the service's subsystems are running.
  bool is_running() const {
    return rpc_is_running_ || writer_thread_ != base::kNullThreadHandle;
  }

  // Begin accepting and handling RPC invocations. This method is not
  // generally callable by clients of the service; it may only be called
  // by the thread which created the service.
  //
  // The request handlers will be run on a thread pool owned by the RPC
  // runtime. If the non_blocking parameter is true, the call to Start()
  // will return immediately, allowing the owning thread to perform other
  // work while the service runs in the background. If non_blocking is
  // false, then the call to Start() will only return when the service
  // receives a shutdown request (via the RequestShutdown() method).
  //
  // Following the receipt of a shutdown request, it is the responsiblity of
  // the thread which owns the service to call Stop() on the service, which
  // will take care of concluding any in-flight requests and flushing all
  // outstanding call trace buffers to disk.
  bool Start(bool non_blocking);

  // Completely shutdown the service. This method is not generally callable
  // by clients of the service; it may only be called by the thread which
  // created, and subsequently started, the service.
  //
  // Following the receipt of a shutdown request, it is the responsiblity of
  // the thread which owns the service to call Stop() on the service, which
  // will take care of concluding any in-flight requests and flushing all
  // outstanding call trace buffers to disk.
  //
  // This is a blocking call, it will return after all outstanding requests
  // have been handled, all call trace buffers have been flushed, all
  // sessions have been closed, and all session resources deallocated.
  bool Stop();

  // RPC implementation of CallTraceControl::Stop().
  // See call_trace_rpc.idl for further info.
  boolean RequestShutdown();

  // RPC implementation of CallTraceService::CreateSession().
  // See call_trace_rpc.idl for further info.
  boolean CreateSession(handle_t binding,
                        SessionHandle* session_handle,
                        CallTraceBuffer* call_trace_buffer,
                        unsigned long* flags);

  // RPC implementation of both CallTraceService::AllocateBuffer().
  // See call_trace_rpc.idl for further info.
  boolean AllocateBuffer(SessionHandle session_handle,
                         CallTraceBuffer* call_trace_buffer);

  // RPC implementation of both CallTraceService::ExchangeBuffer()
  // and CallTraceService::ReturnBuffer(). See call_trace_rpc.idl
  // for further info.
  boolean CommitAndExchangeBuffer(SessionHandle session_handle,
                                  CallTraceBuffer* call_trace_buffer,
                                  ExchangeFlag perform_exchange);

  // RPC implementation of CallTraceService::CloseSession().
  // See call_trace_rpc.idl for further info.
  boolean CloseSession(SessionHandle* session_handle);

  // Allows a session to request its own destruction.
  bool DestroySession(Session* session);

  // @{
  // Inserts the given buffer(s) into the write queue. When writing has been
  // finished the session owning each buffer will be notified via RecycleBuffer.
  // @param buffer the buffer to be written.
  // @params buffers the buffers to be written.
  // @returns true on success, false otherwise.
  bool ScheduleBufferForWriting(Buffer* buffer);
  bool ScheduleBuffersForWriting(const std::vector<Buffer*>& buffers);
  // @}

 // These are protected for unittesting.
 protected:
  typedef std::deque<Buffer*> BufferQueue;

  // Called on the session destruction thread to delete sessions.
  void DoSessionCleanup();

  // RPC Server Management Functions.
  bool AcquireServiceMutex();
  void ReleaseServiceMutex();
  bool InitializeRPC();
  bool RunRPC(bool non_blocking);
  void StopRPC();
  void CleanupRPC();

  // Creates a new session, returning true on success. On failure, the value
  // of *session will be NULL; otherwise it will point to a Session instance.
  // The call trace service retains ownership of the returned Session object;
  // it MUST not be deleted by the caller.
  bool GetNewSession(ProcessId client_process_id, Session** session);

  // Looks up an existing session, returning true on success. On failure,
  // the value of *session will be NULL; otherwise it will point to a
  // Session instance. The call trace service retains ownership of the
  // returned Session object; it MUST not be deleted by the caller.
  bool GetExistingSession(SessionHandle session_handle,
                          Session** session);

  // Gets the next buffer from the buffer pool for the given session,
  // allocating new buffers to the pool as required and returning true
  // on success. On failure, the value of *buffer will be NULL; otherwise,
  // it will point to a Buffer instance owned by the given session; the
  // buffer must not be deleted by the caller.
  bool GetNextBuffer(Session* session, Buffer** buffer);

  // This is a blocking call which waits until the pending write queue
  // is non-empty then transfers (swaps) any pending buffers to be written
  // to out_queue. This function expects that out_queue->empty() is true
  // on input.
  // NOTE: This is virtual for testing purposes. This function is a gateway
  //     that allows us to finely control which buffers get picked up from the
  //     write queue.
  virtual bool GetBuffersToWrite(BufferQueue* out_queue);

  // Launch the writer thread, which will consume buffers from
  // pending_write_queue_ and commit them to disk. Returns true on
  // successfully starting the thread.
  bool StartWriterThread();

  // Signal the write thread to terminate after all buffers currently in
  // pending_write_queue_ are flushed to disk.
  void StopWriterThread();

  // Implements the I/O thread via PlatformThread::Delegate::ThreadMain().
  virtual void ThreadMain();

  // Session factory. This is virtual for testing purposes.
  virtual Session* CreateSession();

  // The collection of active trace sessions.
  typedef std::map<ProcessId, Session*> SessionMap;
  SessionMap sessions_;

  // The instance id to use when running this service instance.
  std::wstring instance_id_;

  // The directory where trace files are stored.
  FilePath trace_directory_;

  // The number of buffers to allocate with each increment.
  size_t num_incremental_buffers_;

  // The number of bytes in each buffer.
  size_t buffer_size_in_bytes_;

  // The maximum number of buffers that a session should have pending write.
  size_t max_buffers_pending_write_;

  // Handle to the thread that owns/created this call trace service instance.
  base::PlatformThreadId owner_thread_;

  // Handle to the thread used for IO.
  base::PlatformThreadHandle writer_thread_;

  // The thread that takes care of session destruction.
  // This is a temporary hack to workaround deadlocks occurring on session
  // destructions.
  // TODO(rogerm): Remove this as you perpetrate the proper fix.
  base::Thread session_destruction_thread_;

  // Protects concurrent access to the internals, except for write-queue
  // related internals.
  base::Lock lock_;

  // Used to detect whether multiple instances of the service are running
  // against the service endpoint.
  base::win::ScopedHandle service_mutex_;

  // Buffers waiting to be written to disk.
  BufferQueue pending_write_queue_;  // Under queue_lock_.
  base::ConditionVariable queue_is_non_empty_;  // Under queue_lock_.
  base::Lock queue_lock_;

  // Flags denoting the state of the RPC server.
  bool rpc_is_initialized_;
  bool rpc_is_running_;
  bool rpc_is_non_blocking_;

  // Flags informing the client of what trace events the service would like
  // to receive.
  uint32 flags_;

  DISALLOW_COPY_AND_ASSIGN(Service);
};

}  // namespace trace::service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_SERVICE_H_
