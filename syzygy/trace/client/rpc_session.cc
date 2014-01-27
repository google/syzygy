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
// A utility class to manage the RPC session and the associated memory mappings.
#include "syzygy/trace/client/rpc_session.h"

#include "syzygy/common/com_utils.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/call_trace_rpc.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace trace {
namespace client {

RpcSession::RpcSession()
    : rpc_binding_(NULL),
      session_handle_(NULL),
      flags_(0),
      is_disabled_(false) {
}

RpcSession::~RpcSession() {
  FreeSharedMemory();
}

bool RpcSession::MapSegmentBuffer(TraceFileSegment* segment) {
  DCHECK(segment != NULL);

  HANDLE mem_handle =
      reinterpret_cast<HANDLE>(segment->buffer_info.shared_memory_handle);

  // Get (or set) the mapping between the handle we've received and the
  // corresponding mapped base pointer. Note that the shared_memory_handles_
  // map is shared across threads, so we need to hold the shared_memory_lock_
  // when we access/update it. This should be the only synchronization point
  // in the call trace client library (other than the initial creation of the
  // RpcSession object, of course).
  {
    base::AutoLock scoped_lock(shared_memory_lock_);

    uint8*& base_ptr = shared_memory_handles_[mem_handle];
    if (base_ptr == NULL) {
      base_ptr = reinterpret_cast<uint8*>(
          ::MapViewOfFile(mem_handle, FILE_MAP_WRITE, 0, 0,
                          segment->buffer_info.mapping_size));
      if (base_ptr == NULL) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "Failed to map view of shared memory: "
                   << ::common::LogWe(error) << ".";
        ignore_result(::CloseHandle(mem_handle));
        shared_memory_handles_.erase(mem_handle);
        return false;
      }
    }

    segment->base_ptr =
        base_ptr + segment->buffer_info.buffer_offset;
  }

  segment->header = NULL;
  segment->write_ptr = segment->base_ptr;
  segment->end_ptr =
      segment->base_ptr + segment->buffer_info.buffer_size;
  segment->WriteSegmentHeader(session_handle_);

  DCHECK(segment->header != NULL);

  return true;
}

bool RpcSession::CreateSession(TraceFileSegment* segment) {
  DCHECK(session_handle_ == NULL);
  DCHECK(rpc_binding_ == NULL);

  std::wstring protocol;
  std::wstring endpoint;
  ::GetSyzygyCallTraceRpcProtocol(&protocol);
  ::GetSyzygyCallTraceRpcEndpoint(instance_id_, &endpoint);

  if (!CreateRpcBinding(protocol, endpoint, &rpc_binding_)) {
    is_disabled_ = true;
    return false;
  }

  DCHECK(rpc_binding_ != 0);

  bool succeeded = InvokeRpc(CallTraceClient_CreateSession,
                             rpc_binding_,
                             &session_handle_,
                             &segment->buffer_info,
                             &flags_).succeeded();

  if (!succeeded) {
    LOG(ERROR) << "Failed to create call trace session!";
    is_disabled_ = true;
    return false;
  }

  if ((flags_ & TRACE_FLAG_BATCH_ENTER) != 0) {
    // Batch mode is mutually exclusive of all other flags.
    flags_ = TRACE_FLAG_BATCH_ENTER;
  }

  if (!MapSegmentBuffer(segment)) {
    is_disabled_ = true;
    return false;
  }

  return true;
}

bool RpcSession::AllocateBuffer(TraceFileSegment* segment) {
  DCHECK(IsTracing());
  DCHECK(segment != NULL);

  bool succeeded = InvokeRpc(CallTraceClient_AllocateBuffer,
                             session_handle_,
                             &segment->buffer_info).succeeded();

  return succeeded ? MapSegmentBuffer(segment) : false;
}

bool RpcSession::AllocateBuffer(size_t min_size, TraceFileSegment* segment) {
  DCHECK(IsTracing());
  DCHECK(segment != NULL);

  // We want the actual buffer to have the provided minimum size. The call is
  // going to prepend the buffer with a RecordPrefix and a
  // TraceFileSegmentHeader, so we make room for those.
  const size_t kHeaderSize = sizeof(RecordPrefix) +
      sizeof(TraceFileSegmentHeader);

  bool succeeded = InvokeRpc(CallTraceClient_AllocateLargeBuffer,
                             session_handle_,
                             min_size + kHeaderSize,
                             &segment->buffer_info).succeeded();
  if (!succeeded)
    return false;

  if (!MapSegmentBuffer(segment))
    return false;

  // We want to make sure the mapped buffer has sufficient size.
  DCHECK(segment->CanAllocateRaw(min_size));

  return true;
}

bool RpcSession::ExchangeBuffer(TraceFileSegment* segment) {
  DCHECK(IsTracing());
  DCHECK(segment != NULL);

  bool succeeded = InvokeRpc(CallTraceClient_ExchangeBuffer,
                             session_handle_,
                             &segment->buffer_info).succeeded();

  return succeeded ? MapSegmentBuffer(segment) : false;
}

bool RpcSession::ReturnBuffer(TraceFileSegment* segment) {
  DCHECK(IsTracing());
  DCHECK(segment != NULL);

  return InvokeRpc(CallTraceClient_ReturnBuffer,
                   session_handle_,
                   &segment->buffer_info).succeeded();
}

bool RpcSession::CloseSession() {
  DCHECK(IsTracing());

  bool succeeded = InvokeRpc(CallTraceClient_CloseSession,
                             &session_handle_).succeeded();

  ignore_result(::RpcBindingFree(&rpc_binding_));
  rpc_binding_ = NULL;

  return succeeded;
}

void RpcSession::FreeSharedMemory() {
  base::AutoLock scoped_lock_(shared_memory_lock_);

  if (shared_memory_handles_.empty())
    return;

  SharedMemoryHandleMap::iterator it = shared_memory_handles_.begin();
  for (; it != shared_memory_handles_.end(); ++it) {
    DCHECK(it->second != NULL);
    if (::UnmapViewOfFile(it->second) == 0) {
      DWORD error = ::GetLastError();
      LOG(WARNING) << "Failed to unmap memory handle: "
                   << ::common::LogWe(error);
    }

    if (::CloseHandle(it->first) == 0) {
      DWORD error = ::GetLastError();
      LOG(WARNING) << "Failed to close memory handle: "
                   << ::common::LogWe(error);
    }
  }

  shared_memory_handles_.clear();
}

}  // namespace client
}  // namespace trace
