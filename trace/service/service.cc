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

// This file defines the call_trace::service::Service class which
// implements the call trace service RPC interface.

#include "syzygy/trace/service/service.h"

#include "base/lazy_instance.h"
#include "base/memory/scoped_ptr.h"
#include "base/string_util.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace call_trace {
namespace service {

// The "global" call trace service singleton.
base::LazyInstance<Service> service_instance = LAZY_INSTANCE_INITIALIZER;

const size_t Service::kDefaultBufferSize = 2 * 1024 * 1024;
const size_t Service::kDefaultNumIncrementalBuffers = 16;
const wchar_t* const Service::kRpcProtocol = ::kCallTraceRpcProtocol;
const wchar_t* const Service::kRpcEndpoint = ::kCallTraceRpcEndpoint;
const wchar_t* const Service::kRpcMutex = ::kCallTraceRpcMutex;

Service::Service()
    : protocol_(kRpcProtocol),
      endpoint_(kRpcEndpoint),
      num_incremental_buffers_(kDefaultNumIncrementalBuffers),
      buffer_size_in_bytes_(kDefaultBufferSize),
      owner_thread_(base::PlatformThread::CurrentId()),
      writer_thread_(base::kNullThreadHandle),
      queue_is_non_empty_(&lock_),
      rpc_is_initialized_(false),
      rpc_is_running_(false),
      rpc_is_non_blocking_(false),
      flags_(TRACE_FLAG_BATCH_ENTER) {
}

Service::~Service() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  Stop();

  DCHECK(sessions_.empty());
}

Service& Service::Instance() {
  return service_instance.Get();
}

bool Service::AcquireServiceMutex() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(!service_mutex_.IsValid());

  base::win::ScopedHandle mutex(::CreateMutex(NULL, FALSE, kRpcMutex));
  if (!mutex.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create mutex: " << com::LogWe(error) << ".";
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
      LOG(ERROR) << "Failed to acquire mutex: " << com::LogWe(error) << ".";
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

bool Service::InitializeRPC()  {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (rpc_is_initialized_) {
    LOG(WARNING) << "The call trace service RPC stack is already initialized.";
    return true;
  }

  RPC_STATUS status = RPC_S_OK;

  // Initialize the RPC protocol we want to use.
  VLOG(1) << "Initializing RPC endpoint '" << endpoint_.c_str() << "' "
      << "using the '" << protocol_.c_str() << "' protocol.";
  status = ::RpcServerUseProtseqEp(
      reinterpret_cast<RPC_WSTR>(&protocol_[0]),
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      reinterpret_cast<RPC_WSTR>(&endpoint_[0]),
      NULL /* Security descriptor. */);
  if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
    LOG(ERROR) << "Failed to init RPC protocol: " << com::LogWe(status) << ".";
    return false;
  }

  // Register the server version of the CallTrace interface.
  VLOG(1) << "Registering the CallTrace interface.";
  status = ::RpcServerRegisterIf(
      CallTraceService_CallTrace_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register CallTrace RPC interface: "
               << com::LogWe(status) << ".";
    return false;
  }

  // Register the server version of the CallTraceControl interface.
  VLOG(1) << "Registering the CallTraceControl interface.";
  status = ::RpcServerRegisterIf(
      CallTraceService_CallTraceControl_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register CallTraceControl RPC interface: "
               << com::LogWe(status) << ".";
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
      non_blocking ? 1 : 0);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to run RPC server: " << com::LogWe(status) << ".";
    rpc_is_running_ = false;
    rpc_is_non_blocking_ = false;
    return false;
  }

  if (rpc_is_non_blocking_) {
    VLOG(1) << "RPC server is running.";
  }

  return true;
}

void Service::StopRPC() {
  if (!rpc_is_running_)
    return;

  // Stop the RPC Server.
  base::AutoLock scoped_lock(lock_);
  if (rpc_is_running_) {
    VLOG(1) << "Stopping RPC server.";
    RPC_STATUS status = ::RpcMgmtStopServerListening(NULL);
    if (status != RPC_S_OK) {
      LOG(ERROR) << "Failed to stop the RPC server: "
                 << com::LogWe(status) << ".";
    }
    rpc_is_running_ = false;
  }
}

void Service::CleanupRPC() {
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
                 << com::LogWe(status) << ".";
    }
    rpc_is_non_blocking_ = false;
  }

  // Unregister the RPC interfaces.
  if (rpc_is_initialized_) {
    VLOG(1) << "Unregistering RPC interfaces.";
    status = ::RpcServerUnregisterIf(NULL, NULL, FALSE);
    if (status != RPC_S_OK) {
      LOG(ERROR) << "Failed to unregister RPC interfaces: "
                 << com::LogWe(status) << ".";
    }
    rpc_is_initialized_ = false;
  }
}

bool Service::Start(bool non_blocking) {
  LOG(INFO) << "Starting the call-trace service.";

  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());

  if (!AcquireServiceMutex())
    return false;

  if (!InitializeRPC()) {
    ReleaseServiceMutex();
    return false;
  }

  if (!StartWriterThread()) {
    CleanupRPC();
    ReleaseServiceMutex();
    return false;
  }

  LOG(INFO) << "The call-trace service is running.";

  return RunRPC(non_blocking);
}

bool Service::Stop() {
  LOG(INFO) << "Stopping the call-trace service.";

  StopRPC();
  CleanupRPC();
  StopWriterThread();
  ReleaseServiceMutex();

  LOG(INFO) << "The call-trace service is stopped.";
  return true;
}

bool Service::StartWriterThread() {
  VLOG(1) << "Starting the trace file IO thread.";

  DCHECK(writer_thread_ == base::kNullThreadHandle);

  if (!base::PlatformThread::Create(0, this, &writer_thread_)) {
    LOG(ERROR) << "Failed to launch IO thread: "
               << com::LogWe(::GetLastError()) << ".";
    return false;
  }

  return true;
}

void Service::StopWriterThread() {
  DCHECK_EQ(owner_thread_, base::PlatformThread::CurrentId());
  DCHECK(!rpc_is_running_);

  if (writer_thread_ == base::kNullThreadHandle) {
    // The writer thread isn't running.
    return;
  }

  VLOG(1) << "Stopping the trace file IO thread.";

  {
    base::AutoLock scoped_lock(lock_);

    // Tell each session that they are to be closed.
    SessionMap::iterator iter = sessions_.begin();
    for (; iter != sessions_.end(); ++iter) {
      iter->second->Close(&pending_write_queue_);
    }

    // Put the shutdown sentinel into the write queue.
    pending_write_queue_.push_back(NULL);
  }

  DCHECK_NE(writer_thread_, base::kNullThreadHandle);

  queue_is_non_empty_.Signal();
  VLOG(1) << "Flushing pending writes.";
  base::PlatformThread::Join(writer_thread_);
  writer_thread_ = base::kNullThreadHandle;
  VLOG(1) << "Trace file IO thread successfully terminated.";
}

bool Service::GetBuffersToWrite(BufferQueue* out_queue) {
  DCHECK(out_queue != NULL);
  DCHECK(out_queue->empty());

  {
    base::AutoLock scoped_lock(lock_);
    while (pending_write_queue_.empty())
      queue_is_non_empty_.Wait();
    out_queue->swap(pending_write_queue_);
  }

  VLOG(1) << "Received " << out_queue->size() << " write buffer(s).";
  DCHECK(!out_queue->empty());

  return true;
}

void Service::ThreadMain() {
  BufferQueue write_queue;
  while (true) {
    GetBuffersToWrite(&write_queue);

    while (!write_queue.empty()) {
      // Get the next buffer to write.
      Buffer* buffer = write_queue.front();
      write_queue.pop_front();

      // Check for the sentinel value telling us to shutdown.
      if (buffer == NULL) {
        DCHECK(write_queue.empty());
        return;
      }

      DCHECK(buffer->write_is_pending);

      // Parse the record prefix and segment header;
      volatile RecordPrefix* prefix =
          reinterpret_cast<RecordPrefix*>(buffer->data_ptr);
      volatile TraceFileSegmentHeader* header =
          reinterpret_cast<volatile TraceFileSegmentHeader*>(prefix + 1);

      // Let's not trust the client to stop playing with the buffer while
      // we're writing. Whatever the length is now, is what we'll use.
      size_t segment_length = header->segment_length;
      const size_t kHeaderLength = sizeof(*prefix) + sizeof(*header);
      if (segment_length > 0) {
        size_t bytes_to_write = common::AlignUp(kHeaderLength + segment_length,
                                                buffer->session->block_size());
        if (prefix->type != TraceFileSegmentHeader::kTypeId ||
            prefix->size != sizeof(TraceFileSegmentHeader) ||
            prefix->version.hi != TRACE_VERSION_HI ||
            prefix->version.lo != TRACE_VERSION_LO) {
          LOG(WARNING) << "Dropped buffer: invalid segment header.";
        } else if (bytes_to_write > buffer->buffer_size) {
          LOG(WARNING) << "Dropped buffer: bytes written exceeds buffer size.";
        } else {
          // Commit the buffer to disk.
          // TODO(rogerm): Use overlapped I/O.
          DCHECK(bytes_to_write != 0);
          DWORD bytes_written = 0;
          if (!::WriteFile(buffer->session->trace_file_handle(),
                           buffer->data_ptr, bytes_to_write,
                           &bytes_written, NULL) ||
              bytes_written != bytes_to_write) {
            DWORD error = ::GetLastError();
            LOG(ERROR) << "Failed writing to '"
                       << buffer->session->trace_file_path().value()
                       << "': " << com::LogWe(error) << ".";
          }
        }
      }

      // Clear the header for the next user of the buffer.
      ::memset(buffer->data_ptr, 0, kHeaderLength);

#ifndef NDEBUG
      // In debug mode, let's clearly identify padding between blocks.
      ::memset(buffer->data_ptr + kHeaderLength, 0xCC,
               buffer->buffer_size - kHeaderLength);
#endif

      buffer->write_is_pending = false;

      // Recycle the buffer to the set of available buffers for this session.
      base::AutoLock scoped_lock(lock_);
      buffer->session->RecycleBuffer(buffer);
    }
  }
}

// RPC entry point.
boolean Service::RequestShutdown() {
  VLOG(1) << "Requesting a shutdown of the call trace service.";

  StopRPC();

  return true;
}

// RPC entry point.
boolean Service::CreateSession(handle_t binding,
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
               << com::LogWe(status) << ".";
    return false;
  }

  ProcessID client_process_id = reinterpret_cast<ProcessID>(attribs.ClientPID);

  VLOG(1) << "Registering client process PID=" << client_process_id << ".";

  base::AutoLock scoped_lock(lock_);

  // Create a new session.
  Session* session = NULL;
  if (!GetNewSession(client_process_id, &session))
    return false;
  DCHECK(session != NULL);

  // Request a buffer for the client.
  Buffer* client_buffer = NULL;
  if (!GetNextBuffer(session, &client_buffer)) {
    DestroySession(session);
    return false;
  }
  DCHECK(client_buffer != NULL);

  // Copy into buffer info into the RPC struct, slicing off the private bits.
  *session_handle = reinterpret_cast<SessionHandle>(session);
  *call_trace_buffer = *client_buffer;
  *flags = flags_;

  return true;
}

// RPC entry point.
boolean Service::AllocateBuffer(SessionHandle session_handle,
                                CallTraceBuffer* call_trace_buffer) {
  if (session_handle == NULL || call_trace_buffer == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  base::AutoLock lock(lock_);

  Session* session = NULL;
  if (!GetExistingSession(session_handle, &session))
    return false;

  // Request a buffer for the client.
  Buffer* client_buffer = NULL;
  if (!GetNextBuffer(session, &client_buffer))
    return false;

  // Copy buffer info into the RPC struct, slicing off the private bits.
  DCHECK(client_buffer != NULL);
  *call_trace_buffer = *client_buffer;

  return true;
}

// RPC entry point.
boolean Service::CommitAndExchangeBuffer(SessionHandle session_handle,
                                         CallTraceBuffer* call_trace_buffer,
                                         ExchangeFlag perform_exchange) {
  if (session_handle == NULL || call_trace_buffer == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  DCHECK(perform_exchange == PERFORM_EXCHANGE ||
         perform_exchange == DO_NOT_PERFORM_EXCHANGE);

  bool result = true;
  {
    base::AutoLock lock(lock_);

    Session* session = NULL;
    if (!GetExistingSession(session_handle, &session))
      return false;

    Buffer* buffer = NULL;
    DCHECK(session != NULL);
    if (!session->FindBuffer(call_trace_buffer, &buffer))
      return false;

    DCHECK(buffer != NULL);
    DCHECK(!buffer->write_is_pending);
    buffer->write_is_pending = true;
    pending_write_queue_.push_back(buffer);

    ZeroMemory(call_trace_buffer, sizeof(*call_trace_buffer));

    if (perform_exchange == PERFORM_EXCHANGE) {
      // Request a buffer for the client.
      Buffer* client_buffer = NULL;
      if (!GetNextBuffer(session, &client_buffer)) {
        result = false;
      } else {
        // Copy buffer info into the RPC struct, slicing off the private bits.
        DCHECK(client_buffer != NULL);
        *call_trace_buffer = *client_buffer;
      }
    }
  }

  queue_is_non_empty_.Signal();

  return result;
}

// RPC entry-point.
boolean Service::CloseSession(SessionHandle* session_handle) {
  if (session_handle == NULL || *session_handle == NULL) {
    LOG(WARNING) << "Invalid RPC parameters.";
    return false;
  }

  {
    base::AutoLock lock(lock_);

    Session* session = NULL;
    if (!GetExistingSession(*session_handle, &session))
      return false;

    // Signal that we want the session to close. This will cause it to
    // schedule all of its oustanding buffer for flushing via
    // pending_write_queue_.
    session->Close(&pending_write_queue_);
  }

  queue_is_non_empty_.Signal();
  *session_handle = NULL;

  return true;
}

bool Service::DestroySession(Session* session) {
  DCHECK(session != NULL);
  lock_.AssertAcquired();

  if (sessions_.erase(session->client_process_id()) == 0) {
    LOG(ERROR) << "Destroying unknown session!";
    return false;
  }

  delete session;

  return true;
}

bool Service::GetNewSession(ProcessID client_process_id, Session** session) {
  DCHECK(session != NULL);
  lock_.AssertAcquired();

  *session = NULL;

  // Take care of deleting the session if initialization fails or a session
  // already exists for this pid.
  scoped_ptr<Session> new_session(new Session(this));

  // Attempt to add the session to the session map. If the insertion fails,
  // let the new_session scoped_ptr clean up the object.
  std::pair<SessionMap::iterator, bool> result = sessions_.insert(
      SessionMap::value_type(client_process_id, new_session.get()));
  if (result.second == false) {
    LOG(ERROR) << "A session already exists for process " << client_process_id
        << ".";
    return false;
  }

  // Initialize the session. Remove the session record if initialization
  // fails. The new_session scoped_ptr will take care of destroying the
  // actual session object.
  if (!new_session->Init(trace_directory_, client_process_id)) {
    sessions_.erase(result.first);
    return false;
  }

  // The session map has taken ownership of the session object; release
  // and return the session pointer.
  *session = new_session.release();

  return true;
}

bool Service::GetExistingSession(SessionHandle session_handle,
                                 Session** session) {
  DCHECK(session != NULL);
  lock_.AssertAcquired();

  *session = reinterpret_cast<Session*>(session_handle);

#ifndef NDEBUG
  if (sessions_.find((*session)->client_process_id()) == sessions_.end()) {
    LOG(ERROR) << "No session exists for handle " << session_handle << ".";
    *session = NULL;
    return false;
  }
#endif

  return true;
}

bool Service::GetNextBuffer(Session* session, Buffer** buffer) {
  DCHECK(session != NULL);
  DCHECK(buffer != NULL);

  lock_.AssertAcquired();

  *buffer = NULL;

  if (!session->HasAvailableBuffers() &&
      !session->AllocateBuffers(num_incremental_buffers_,
                                buffer_size_in_bytes_)) {
    return false;
  }

  return session->GetNextBuffer(buffer);
}

}  // namespace call_trace::service
}  // namespace call_trace
