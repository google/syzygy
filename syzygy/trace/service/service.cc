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
// This file defines the trace::service::Service class which
// implements the call trace service RPC interface.
//
// TODO(rogerm): Use server controlled context handles to refer to the buffers
//     across the RPC boundary. The shared memory handle is client controlled
//     and not necessarily unique.

#include "syzygy/trace/service/service.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_util.h"
#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/buffer_consumer.h"
#include "syzygy/trace/service/session.h"

namespace trace {
namespace service {

const size_t Service::kDefaultBufferSize = 2 * 1024 * 1024;
const size_t Service::kDefaultNumIncrementalBuffers = 16;

// The choice of this value is not particularly important, but it should be
// something that is relatively prime to the number of buffers created per
// allocation, and it should represent more memory than our disk bandwidth
// can reasonably write in about a second or so, so as to allow sufficient
// buffering for smoothing. Assuming 20MB/sec consistent throughput, this
// represents about 26 MB, so 1.3 seconds of disk bandwidth.
const size_t Service::kDefaultMaxBuffersPendingWrite = 13;

Service::Service(BufferConsumerFactory* factory)
    : num_active_sessions_(0),
      num_incremental_buffers_(kDefaultNumIncrementalBuffers),
      buffer_size_in_bytes_(kDefaultBufferSize),
      max_buffers_pending_write_(kDefaultMaxBuffersPendingWrite),
      owner_thread_(base::PlatformThread::CurrentId()),
      buffer_consumer_factory_(factory),
      a_session_has_closed_(&lock_),
      rpc_is_initialized_(false),
      rpc_is_running_(false),
      rpc_is_non_blocking_(false),
      flags_(TRACE_FLAG_BATCH_ENTER) {
  DCHECK(factory != NULL);
}

Service::~Service() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(buffer_consumer_factory_ != NULL);

  Stop();

  DCHECK(sessions_.empty());
  DCHECK_EQ(0U, num_active_sessions_);
}

void Service::AddOneActiveSession() {
  base::AutoLock auto_lock(lock_);

  ++num_active_sessions_;
}

void Service::RemoveOneActiveSession() {
  {
    base::AutoLock auto_lock(lock_);
    DCHECK_LT(0u, num_active_sessions_);

    --num_active_sessions_;
  }

  a_session_has_closed_.Signal();
}

bool Service::OpenServiceEvent() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(!service_event_.IsValid());

  std::wstring event_name;
  ::GetSyzygyCallTraceRpcEventName(instance_id_, &event_name);

  service_event_.Set(::CreateEvent(NULL, TRUE, FALSE, event_name.c_str()));
  if (!service_event_.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create event: " << ::common::LogWe(error) << ".";
    return false;
  }

  return true;
}

bool Service::AcquireServiceMutex() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(!service_mutex_.IsValid());

  std::wstring mutex_name;
  ::GetSyzygyCallTraceRpcMutexName(instance_id_, &mutex_name);
  base::win::ScopedHandle mutex(::CreateMutex(NULL, FALSE, mutex_name.c_str()));
  if (!mutex.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create mutex: " << ::common::LogWe(error) << ".";
    return false;
  }
  const DWORD kOneSecondInMs = 1000;

  switch (::WaitForSingleObject(mutex, kOneSecondInMs)) {
    case WAIT_ABANDONED:
      LOG(WARNING) << "Orphaned service mutex found!";
      // Fall through...

    case WAIT_OBJECT_0:
      VLOG(1) << "Service mutex acquired.";
      service_mutex_.Set(mutex.Take());
      return true;

    case WAIT_TIMEOUT:
      LOG(ERROR) << "Another instance of the service is running.";
      break;

    default: {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "Failed to acquire mutex: " << ::common::LogWe(error)
                 << ".";
      break;
    }
  }
  return false;
}

void Service::ReleaseServiceMutex() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (service_mutex_.IsValid()) {
    ::ReleaseMutex(service_mutex_);
    service_mutex_.Close();
  }
}

bool Service::InitializeRpc()  {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (rpc_is_initialized_) {
    LOG(WARNING) << "The call trace service RPC stack is already initialized.";
    return true;
  }

  RPC_STATUS status = RPC_S_OK;

  // Initialize the RPC protocol we want to use.
  std::wstring protocol;
  std::wstring endpoint;
  ::GetSyzygyCallTraceRpcProtocol(&protocol);
  ::GetSyzygyCallTraceRpcEndpoint(instance_id_, &endpoint);

  VLOG(1) << "Initializing RPC endpoint '" << endpoint << "' "
          << "using the '" << protocol << "' protocol.";
  status = ::RpcServerUseProtseqEp(
      reinterpret_cast<RPC_WSTR>(&protocol[0]),
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      reinterpret_cast<RPC_WSTR>(&endpoint[0]),
      NULL /* Security descriptor. */);
  if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
    LOG(ERROR) << "Failed to init RPC protocol: " << ::common::LogWe(status)
               << ".";
    return false;
  }

  // Register the server version of the CallTrace interface.
  VLOG(1) << "Registering the CallTrace interface.";
  status = ::RpcServerRegisterIf(
      CallTraceService_CallTrace_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register CallTrace RPC interface: "
               << ::common::LogWe(status) << ".";
    return false;
  }

  // Register the server version of the CallTraceControl interface.
  VLOG(1) << "Registering the CallTraceControl interface.";
  status = ::RpcServerRegisterIf(
      CallTraceService_CallTraceControl_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register CallTraceControl RPC interface: "
               << ::common::LogWe(status) << ".";
    return false;
  }

  rpc_is_initialized_ = true;
  return true;
}

bool Service::RunRPC(bool non_blocking) {
  VLOG(1) << "Starting the RPC server.";

  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (rpc_is_running_) {
    LOG(ERROR) << "The RPC server is already running.";
    return false;
  }

  rpc_is_running_ = true;
  rpc_is_non_blocking_ = non_blocking;

  RPC_STATUS status = ::RpcServerListen(
      1,  // Minimum number of handler threads.
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      TRUE);

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to run RPC server: " << ::common::LogWe(status)
               << ".";
  }

  if (status == RPC_S_OK) {
    // Signal that the service is up and running.
    DCHECK(service_event_.IsValid());
    BOOL success = ::SetEvent(service_event_.Get());
    DCHECK_EQ(TRUE, success);

    // Wait here if we're in blocking mode.
    if (!non_blocking) {
      VLOG(1) << "Call-trace service is running in blocking mode.";
      status = RpcMgmtWaitServerListen();

      if (status == RPC_S_OK) {
        VLOG(1) << "Call-trace service has finished accepting requests.";
      } else {
        LOG(ERROR) << "Failed to wait on RPC server: "
                   << ::common::LogWe(status) << ".";
      }
    }
  }

  if (status != RPC_S_OK) {
    rpc_is_running_ = false;
    rpc_is_non_blocking_ = false;
    return false;
  }

  if (rpc_is_non_blocking_)
    VLOG(1) << "Call-trace service is running in non-blocking mode.";

  return true;
}

void Service::StopRpc() {
  if (!rpc_is_running_)
    return;

  // Stop the RPC Server.
  base::AutoLock auto_lock(lock_);
  if (rpc_is_running_) {
    VLOG(1) << "Stopping RPC server.";
    RPC_STATUS status = ::RpcMgmtStopServerListening(NULL);
    if (status != RPC_S_OK) {
      LOG(ERROR) << "Failed to stop the RPC server: "
                 << ::common::LogWe(status) << ".";
    }
    rpc_is_running_ = false;
  }
}

void Service::CleanupRpc() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(rpc_is_running_ == false);

  RPC_STATUS status = RPC_S_OK;

  // If we're running in non-blocking mode, then we have to wait for
  // any in-flight RPC requests to terminate.
  if (rpc_is_non_blocking_) {
    VLOG(1) << "Waiting for outstanding RPC requests to terminate.";
    status = ::RpcMgmtWaitServerListen();
    if (status != RPC_S_OK && status != RPC_S_NOT_LISTENING) {
      LOG(ERROR) << "Failed wait for RPC server shutdown: "
                 << ::common::LogWe(status) << ".";
    }
    rpc_is_non_blocking_ = false;
  }

  // Unregister the RPC interfaces.
  if (rpc_is_initialized_) {
    VLOG(1) << "Unregistering RPC interfaces.";
    status = ::RpcServerUnregisterIf(NULL, NULL, FALSE);
    if (status != RPC_S_OK) {
      LOG(ERROR) << "Failed to unregister RPC interfaces: "
                 << ::common::LogWe(status) << ".";
    }
    rpc_is_initialized_ = false;
  }
}

bool Service::Start(bool non_blocking) {
  LOG(INFO) << "Starting the call-trace service.";

  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (!AcquireServiceMutex())
    return false;

  if (!OpenServiceEvent())
    return false;

  if (!InitializeRpc()) {
    ReleaseServiceMutex();
    return false;
  }

  LOG(INFO) << "The call-trace service is running.";

  if (!RunRPC(non_blocking))
    return false;

  LOG(INFO) << "The call-trace service is no longer running.";

  return true;
}

bool Service::Stop() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  LOG(INFO) << "Stopping the call-trace service.";

  StopRpc();
  CleanupRpc();
  CloseAllOpenSessions();
  ReleaseServiceMutex();

  // Signal that we've shut down.
  if (service_event_.IsValid())
    ::ResetEvent(service_event_.Get());

  LOG(INFO) << "The call-trace service is stopped.";
  return true;
}

bool Service::CloseAllOpenSessions() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(!rpc_is_running_);

  VLOG(1) << "Flushing all outstanding buffers.";

  SessionMap to_close;
  {
    base::AutoLock auto_lock(lock_);
    to_close.swap(sessions_);

    DCHECK(sessions_.empty());
  }

  // Tell each session that they are to be closed. This will get them to
  // flush all outstanding buffers to their respective consumers.
  SessionMap::iterator iter = to_close.begin();
  for (; iter != to_close.end(); ++iter) {
    iter->second->Close();
  }

  // Release the references we hold to the closing sessions.
  to_close.clear();

  // Wait until all pending sessions have closed.
  {
    base::AutoLock auto_lock(lock_);

    int pending_sessions = 0;
    while ((pending_sessions = num_active_sessions_) != 0) {
      VLOG(1) << "There are " << pending_sessions << " pending sessions.";
      a_session_has_closed_.Wait();
    }
  }

  return true;
}

Session* Service::CreateSession() {
  return new Session(this);
}

// RPC entry point.
bool Service::RequestShutdown() {
  VLOG(1) << "Requesting a shutdown of the call trace service.";

  StopRpc();

  return true;
}

// RPC entry point.
bool Service::CreateSession(handle_t binding,
                            SessionHandle* session_handle,
                            CallTraceBuffer* call_trace_buffer,
                            unsigned long* flags) {
  if (binding == NULL || session_handle == NULL || call_trace_buffer == NULL ||
      flags == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }
  const int kVersion = 2;
  RPC_CALL_ATTRIBUTES_V2 attribs = { kVersion, RPC_QUERY_CLIENT_PID };
  RPC_STATUS status = RpcServerInqCallAttributes(binding, &attribs);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to query RPC call attributes: "
               << ::common::LogWe(status) << ".";
    return false;
  }

  ProcessId client_process_id = reinterpret_cast<ProcessId>(attribs.ClientPID);

  VLOG(1) << "Registering client process PID=" << client_process_id << ".";

  scoped_refptr<Session> session;
  if (!GetNewSession(client_process_id, &session))
    return false;

  DCHECK(session.get() != NULL);

  // Request a buffer for the client.
  Buffer* client_buffer = NULL;
  if (!session->GetNextBuffer(&client_buffer)) {
    sessions_.erase(session->client_process_id());
    session->Close();
    return false;
  }
  DCHECK(client_buffer != NULL);

  // Copy buffer info into the RPC struct, slicing off the private bits.
  *session_handle = reinterpret_cast<SessionHandle>(session.get());
  *call_trace_buffer = *client_buffer;
  *flags = flags_;

  return true;
}

// RPC entry point.
bool Service::AllocateBuffer(SessionHandle session_handle,
                             CallTraceBuffer* call_trace_buffer) {
  if (session_handle == NULL || call_trace_buffer == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  scoped_refptr<Session> session;
  if (!GetExistingSession(session_handle, &session))
    return false;
  DCHECK(session.get() != NULL);

  // Request a buffer for the client.
  Buffer* client_buffer = NULL;
  if (!session->GetNextBuffer(&client_buffer))
    return false;

  // Copy buffer info into the RPC struct, slicing off the private bits.
  DCHECK(client_buffer != NULL);
  *call_trace_buffer = *client_buffer;

  return true;
}

// RPC entry point.
bool Service::AllocateLargeBuffer(SessionHandle session_handle,
                                  size_t minimum_size,
                                  CallTraceBuffer* call_trace_buffer) {
  if (session_handle == NULL || call_trace_buffer == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  scoped_refptr<Session> session;
  if (!GetExistingSession(session_handle, &session))
    return false;
  DCHECK(session.get() != NULL);

  // Request a buffer for the client.
  Buffer* client_buffer = NULL;
  if (!session->GetBuffer(minimum_size, &client_buffer))
    return false;

  // Copy buffer info into the RPC struct, slicing off the private bits.
  DCHECK(client_buffer != NULL);
  *call_trace_buffer = *client_buffer;

  return true;
}

// RPC entry point.
bool Service::CommitAndExchangeBuffer(SessionHandle session_handle,
                                      CallTraceBuffer* call_trace_buffer,
                                      ExchangeFlag perform_exchange) {
  if (session_handle == NULL || call_trace_buffer == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  DCHECK(perform_exchange == PERFORM_EXCHANGE ||
         perform_exchange == DO_NOT_PERFORM_EXCHANGE);

  bool result = true;
  scoped_refptr<Session> session;
  if (!GetExistingSession(session_handle, &session))
    return false;
  DCHECK(session.get() != NULL);

  Buffer* buffer = NULL;
  if (!session->FindBuffer(call_trace_buffer, &buffer))
    return false;

  DCHECK(buffer != NULL);

  // We can't say anything about the buffer's state, as it possible that the
  // session that owns it has already been asked to shutdown, in which case
  // all of its buffers have already been scheduled for writing and the call
  // below will be ignored.

  // Return the buffer to the session. The session will then take care of
  // scheduling it for writing. Currently, it feeds it right back to us, but
  // this routing allows the write-queue to be decoupled from the service
  // more easily in the future.
  if (!session->ReturnBuffer(buffer)) {
    LOG(ERROR) << "Unable to return buffer to session.";
    return false;
  }

  ZeroMemory(call_trace_buffer, sizeof(*call_trace_buffer));

  if (perform_exchange == PERFORM_EXCHANGE) {
    // Request a buffer for the client.
    Buffer* client_buffer = NULL;
    if (!session->GetNextBuffer(&client_buffer)) {
      result = false;
    } else {
      // Copy buffer info into the RPC struct, slicing off the private bits.
      DCHECK(client_buffer != NULL);
      *call_trace_buffer = *client_buffer;
    }
  }

  return result;
}

// RPC entry-point.
bool Service::CloseSession(SessionHandle* session_handle) {
  if (session_handle == NULL || *session_handle == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  scoped_refptr<Session> session;
  {
    base::AutoLock auto_lock(lock_);

    if (!GetExistingSessionUnlocked(*session_handle, &session))
      return false;

    size_t num_erased = sessions_.erase(session->client_process_id());
    DCHECK_EQ(1U, num_erased);
  }

  DCHECK(session.get() != NULL);

  // Signal that we want the session to close. This will cause it to
  // schedule all of its outstanding buffers for writing. It will destroy
  // itself once it's reference count drops to zero.
  session->Close();

  *session_handle = NULL;

  return true;
}

bool Service::GetNewSession(ProcessId client_process_id,
                            scoped_refptr<Session>* session) {
  DCHECK(session != NULL);
  *session = NULL;

  // Create the new session.
  scoped_refptr<Session> new_session(CreateSession());
  if (new_session.get() == NULL)
    return false;

  // Initialize the session.
  if (!new_session->Init(client_process_id))
    return false;

  // Allocate a new buffer consumer.
  scoped_refptr<BufferConsumer> consumer;
  if (!buffer_consumer_factory_->CreateConsumer(&consumer))
    return false;

  // Open the buffer consumer.
  if (!consumer->Open(new_session))
    return false;

  // Hand the buffer consumer over to the session. The session will direct
  // returned buffers to the consumer.
  new_session->set_buffer_consumer(consumer);

  bool inserted = false;
  {
    base::AutoLock auto_lock(lock_);
    // Attempt to add the session to the session map.
    inserted = sessions_.insert(
        SessionMap::value_type(client_process_id, new_session)).second;
  }

  if (inserted == false) {
    LOG(ERROR) << "A session already exists for process " << client_process_id
        << ".";
    consumer->Close(new_session.get());
    CHECK(new_session->Close());

    return false;
  }

  // The session map has taken ownership of the session object; release
  // and return the session pointer.
  *session = new_session;

  return true;
}

bool Service::GetExistingSession(SessionHandle session_handle,
                                 scoped_refptr<Session>* session) {
  DCHECK(session != NULL);
  base::AutoLock auto_lock(lock_);

  return GetExistingSessionUnlocked(session_handle, session);
}

bool Service::GetExistingSessionUnlocked(SessionHandle session_handle,
                                         scoped_refptr<Session>* session) {
  DCHECK(session != NULL);
  lock_.AssertAcquired();

  *session = reinterpret_cast<Session*>(session_handle);

#ifndef NDEBUG
  if (sessions_.find((*session)->client_process_id()) == sessions_.end()) {
    LOG(ERROR) << "No session exists for handle " << session_handle << ".";
    *session = static_cast<Session*>(NULL);
    return false;
  }
#endif

  return true;
}

}  // namespace service
}  // namespace trace
