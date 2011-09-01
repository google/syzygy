// Copyright 2011 Google Inc.
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
// This file declares the call_trace::service::Service class which implements
// the call trace service RPC interface.

#ifndef SYZYGY_CALL_TRACE_SERVICE_H_
#define SYZYGY_CALL_TRACE_SERVICE_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/platform_thread.h"
#include "syzygy/call_trace/session.h"

namespace call_trace {
namespace service {

// Implements the CallTraceService interface (see "call_trace_rpc.idl".
// For the most basic usage:
//
//   call_trace::service::Service::Instance().Start(false);
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

  // The name of the Win32 RPC protocol to which the service will bind.
  static const wchar_t* const kRpcProtocol;

  // The name/address of the RPC endpoint at which the service will listen.
  static const wchar_t* const kRpcEndpoint;

  // Set the directory where trace files are stored.
  void set_trace_directory(const FilePath& directory) {
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
                        const wchar_t* command_line,
                        SessionHandle* session_handle,
                        CallTraceBuffer* call_trace_buffer);

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

 private:
  // RPC Server Management Functions.
  bool InitializeRPC();
  bool RunRPC(bool non_blocking);
  void StopRPC();
  void CleanupRPC();

  // Creates a new session, returning true on success. On failure, the value
  // of *session will be NULL; otherwise it will point to a Session instance.
  // The call trace service retains ownership of the returned Session object;
  // it MUST not be deleted by the caller.
  bool GetNewSession(ProcessID client_process_id,
                     const wchar_t* command_line,
                     Session** session);

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
  bool GetBuffersToWrite(BufferQueue* out_queue);

  // Launch the writer thread, which will consume buffers from
  // pending_write_queue_ and commit them to disk. Returns true on
  // successfully starting the thread.
  bool StartWriterThread();

  // Signal the write thread to terminate after all buffers currently in
  // pending_write_queue_ are flushed to disk.
  void StopWriterThread();

  // Implements the I/O thread via PlatformThread::Delegate::ThreadMain().
  virtual void ThreadMain();

  // The collection of active trace sessions.
  SessionMap sessions_;

  // The RPC protocol to use.
  std::wstring protocol_;

  // The RPC endpoing to bind.
  std::wstring endpoint_;

  // The directory where trace files are stored.
  FilePath trace_directory_;

  // The number of buffers to allocate with each increment.
  size_t num_incremental_buffers_;

  // The number of bytes in each buffer.
  size_t buffer_size_in_bytes_;

  // Handle to the thread that owns/created this call trace service instance.
  base::PlatformThreadId owner_thread_;

  // Handle to the thread used for IO.
  base::PlatformThreadHandle writer_thread_;

  // Protects concurrent access to the internals.
  base::Lock lock_;

  // Buffers waiting to be written to disk.
  BufferQueue pending_write_queue_;
  base::ConditionVariable queue_is_non_empty_;

  // Flags denoting the state of the RPC server.
  bool rpc_is_initialized_;
  bool rpc_is_running_;
  bool rpc_is_non_blocking_;

  DISALLOW_COPY_AND_ASSIGN(Service);
};

}  // namespace call_trace::service
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_SERVICE_H_
