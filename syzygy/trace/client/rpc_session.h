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

#ifndef SYZYGY_TRACE_CLIENT_RPC_SESSION_H_
#define SYZYGY_TRACE_CLIENT_RPC_SESSION_H_

#include <map>

#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace trace {
namespace client {

class RpcSession {
 public:
  RpcSession();
  ~RpcSession();

  // Set the instance identifier for this session.
  void set_instance_id(const base::StringPiece16& instance_id) {
    DCHECK(!IsTracing());
    instance_id_.assign(instance_id.begin(), instance_id.end());
  }

  // @returns the instance ID for this session.
  const std::wstring instance_id() const { return instance_id_; }

  // @name Wrapper and helper functions for the RPC and shared memory calls made
  // by the call-trace client. These are virtual for ease of unittesting.
  // @{

  // @note Do not call this function directly unless you know exactly what
  //     you're doing. For consistent semantics across agents please use
  //     trace::client::InitializeRpcSession.
  virtual bool CreateSession(TraceFileSegment* segment);
  virtual bool AllocateBuffer(TraceFileSegment* segment);
  virtual bool AllocateBuffer(size_t min_size, TraceFileSegment* segment);
  virtual bool ExchangeBuffer(TraceFileSegment* segment);
  virtual bool ReturnBuffer(TraceFileSegment* segment);
  virtual bool CloseSession();
  virtual void FreeSharedMemory();
  // @}

  inline bool IsEnabled(unsigned long bit_mask) const {
    return (flags_ & bit_mask) != 0;
  }

  bool IsTracing() const {
    return session_handle_ != NULL;
  }

  bool IsDisabled() const {
    return is_disabled_;
  }

  unsigned long flags() const { return flags_; }

 protected:
  // Map a tracefile segment buffer into local memory.
  bool MapSegmentBuffer(TraceFileSegment* segment);

  // The call trace RPC binding.
  handle_t rpc_binding_;

  // The handle to the call trace session. Initialization of the session
  // is protected by a lock. This is a separate lock since we don't seem
  // to have recursive locks in base.
  SessionHandle session_handle_;

  // The set of trace flags returned by the call trace server. These instruct
  // the client as to which types of events to capture.
  unsigned long flags_;

  // We track the set of shared memory handles we've mapped into the
  // process. This allows us to avoid mapping a handle twice, as well
  // as letting us know what to clean up on exit. Access to the set
  // of handles must be serialized with a lock.
  typedef std::map<HANDLE, uint8_t*> SharedMemoryHandleMap;
  base::Lock shared_memory_lock_;
  SharedMemoryHandleMap shared_memory_handles_;

  // This becomes true if the client fails to attach to a call trace service.
  // This is used to allow the application to run even if no call trace
  // service is available.
  bool is_disabled_;

  // The (optional) unique id used to differentiate concurrent instances of the
  // RPC call-trace logging service.
  std::wstring instance_id_;
};

}  // namespace client
}  // namespace trace

#endif  // SYZYGY_TRACE_CLIENT_RPC_SESSION_H_
