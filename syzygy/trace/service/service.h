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
// This file declares the trace::service::Service class which implements
// the call trace service RPC interface.

#ifndef SYZYGY_TRACE_SERVICE_SERVICE_H_
#define SYZYGY_TRACE_SERVICE_SERVICE_H_

#include <map>

#include "base/basictypes.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/process/process.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "syzygy/trace/rpc/call_trace_rpc.h"

namespace trace {
namespace service {

// Forward declarations.
class BufferConsumerFactory;
class Session;

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
class Service {
 public:
  typedef base::ProcessId ProcessId;

  // Flag passed to CommitAndExchangeBuffer() to determine whether or
  // not a fresh buffer should be returned to the client.
  enum ExchangeFlag {
    DO_NOT_PERFORM_EXCHANGE,
    PERFORM_EXCHANGE
  };

  // Construct a new call trace Service instance. The service will use the
  // given @p factory to construct buffer consumers for new sessions. The
  // service instance does NOT take ownership of the @p factory, which must
  // exist at least until the service instance is destroyed.
  explicit Service(BufferConsumerFactory* factory);
  ~Service();

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
    return rpc_is_running_ || num_active_sessions_ > 0;
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
  // Following the receipt of a shutdown request, it is the responsibility of
  // the thread which owns the service to call Stop() on the service, which
  // will take care of concluding any in-flight requests and flushing all
  // outstanding call trace buffers to disk.
  bool Start(bool non_blocking);

  // Completely shutdown the service. This method is not generally callable
  // by clients of the service; it may only be called by the thread which
  // created, and subsequently started, the service.
  //
  // Following the receipt of a shutdown request, it is the responsibility of
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
  bool RequestShutdown();

  // RPC implementation of CallTraceService::CreateSession().
  // See call_trace_rpc.idl for further info.
  bool CreateSession(handle_t binding,
                     SessionHandle* session_handle,
                     CallTraceBuffer* call_trace_buffer,
                     unsigned long* flags);

  // RPC implementation of CallTraceService::AllocateBuffer().
  // See call_trace_rpc.idl for further info.
  bool AllocateBuffer(SessionHandle session_handle,
                      CallTraceBuffer* call_trace_buffer);

  // RPC implementation of CallTraceService::AllocateLargeBuffer().
  // See call_trace_rpc.idl for further info.
  bool AllocateLargeBuffer(SessionHandle session_handle,
                           size_t minimum_size,
                           CallTraceBuffer* call_trace_buffer);

  // RPC implementation of both CallTraceService::ExchangeBuffer()
  // and CallTraceService::ReturnBuffer(). See call_trace_rpc.idl
  // for further info.
  bool CommitAndExchangeBuffer(SessionHandle session_handle,
                               CallTraceBuffer* call_trace_buffer,
                               ExchangeFlag perform_exchange);

  // RPC implementation of CallTraceService::CloseSession().
  // See call_trace_rpc.idl for further info.
  bool CloseSession(SessionHandle* session_handle);

  // Decrement the active session count.
  // @see num_active_sessions_
  void RemoveOneActiveSession();

  // Increment the active session count.
  // @see num_active_sessions_.
  void AddOneActiveSession();

 // These are protected for unittesting.
 protected:

  // @name RPC Server Management Functions.
  // These functions, unless otherwise noted, are single threaded and must
  // all be called from the thread that created this instance.
  // @{
  bool OpenServiceEvent();
  bool AcquireServiceMutex();
  void ReleaseServiceMutex();
  bool InitializeRpc();
  bool RunRPC(bool non_blocking);

  // This function is thread-safe.
  void StopRpc();
  void CleanupRpc();
  // @}

  // Creates a new session, returning true on success. On failure, the value
  // of *session will be NULL; otherwise it will contain a Session reference.
  bool GetNewSession(ProcessId client_process_id,
                     scoped_refptr<Session>* session);

  // Looks up an existing session, returning true on success. On failure,
  // the value of *session will be NULL; otherwise it will contain a
  // Session reference.
  bool GetExistingSession(SessionHandle session_handle,
                          scoped_refptr<Session>* session);
  // Looks up an existing session, returning true on success. On failure,
  // the value of *session will be NULL; otherwise it will contain a
  // Session reference.
  bool GetExistingSessionUnlocked(SessionHandle session_handle,
                                  scoped_refptr<Session>* session);

  // Closes all open sessions. This call blocks until all sessions have been
  // shutdown and have finished flushing their buffers.
  bool CloseAllOpenSessions();

  // Session factory. This is virtual for testing purposes.
  virtual Session* CreateSession();

  // Protects concurrent access to the internals, except for write-queue
  // related internals.
  base::Lock lock_;

  // The collection of open trace sessions. This is the collection of sessions
  // for which the service is currently accepting requests. Once a session is
  // closed, it is removed from this collection, but may still be active for
  // some time as it's trace buffers are consumed. See num_active_sessions_.
  typedef std::map<ProcessId, scoped_refptr<Session>> SessionMap;
  SessionMap sessions_;  // Under lock_.

  // A count of the number of active sessions currently managed by this service.
  // This includes both open sessions and closed sessions which have not yet
  // finished flushing their buffers.
  size_t num_active_sessions_;  // Under lock_.

  // The instance id to use when running this service instance.
  std::wstring instance_id_;

  // The number of buffers to allocate with each increment.
  size_t num_incremental_buffers_;

  // The number of bytes in each buffer.
  size_t buffer_size_in_bytes_;

  // The maximum number of buffers that a session should have pending write.
  size_t max_buffers_pending_write_;

  // Handle to the thread that owns/created this call trace service instance.
  base::PlatformThreadId owner_thread_;

  // The source factory for buffer consumer objects.
  BufferConsumerFactory* buffer_consumer_factory_;

  // Used to wait for all sessions to be closed on service shutdown.
  base::ConditionVariable a_session_has_closed_;  // Under lock_.

  // Used to detect whether multiple instances of the service are running
  // against the service endpoint.
  base::win::ScopedHandle service_mutex_;

  // Signaled once the service has successfully initialized.
  base::win::ScopedHandle service_event_;

  // Flags denoting the state of the RPC server.
  bool rpc_is_initialized_;
  // TODO(rogerm): Access to this flag is inconsistent, but it seems the
  //    transition from true to false will always take place under lock_.
  bool rpc_is_running_;  // Under lock_.
  bool rpc_is_non_blocking_;

  // Flags informing the client of what trace events the service would like
  // to receive.
  uint32 flags_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Service);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_SERVICE_H_
