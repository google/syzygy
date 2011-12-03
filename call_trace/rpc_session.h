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
// A utility class to manage the RPC session and the associated memory mappings.

#ifndef SYZYGY_CALL_TRACE_RPC_SESSION_H_
#define SYZYGY_CALL_TRACE_RPC_SESSION_H_

#include <map>

#include "base/synchronization/lock.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/client_utils.h"

namespace call_trace {
namespace client {

class RpcSession {
 public:
  RpcSession();
  ~RpcSession();

  // Wrapper and helper functions for the RPC and shared memory calls made
  // by the call-trace client.
  bool CreateSession(TraceFileSegment* segment);
  bool AllocateBuffer(TraceFileSegment* segment);
  bool ExchangeBuffer(TraceFileSegment* segment);
  bool ReturnBuffer(TraceFileSegment* segment);
  bool CloseSession();
  void FreeSharedMemory();

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

 private:
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
  typedef std::map<HANDLE, uint8*> SharedMemoryHandleMap;
  base::Lock shared_memory_lock_;
  SharedMemoryHandleMap shared_memory_handles_;

  // This becomes true if the client fails to attach to a call trace service.
  // This is used to allow the application to run even if no call trace
  // service is available.
  bool is_disabled_;
};

}  // namespace call_trace::client
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_RPC_SESSION_H_
