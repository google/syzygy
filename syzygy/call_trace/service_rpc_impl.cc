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

// This file implements the RPC stubs which bind the CallTraceService RPC
// handlers to the lazily initialized static call_trace::service::Service
// instance.

#include "syzygy/call_trace/service.h"

using call_trace::service::Service;

// RPC entrypoint for CallTraceService::CreateSession().
boolean CallTraceService_CreateSession(
    /* [in] */ handle_t binding,
    /* [out] */ SessionHandle* session_handle,
    /* [out] */ CallTraceBuffer* call_trace_buffer,
    /* [out] */ unsigned long* flags) {
  // Delegate the call to the call trace service instance.
  return Service::Instance().CreateSession(binding,
                                           session_handle,
                                           call_trace_buffer,
                                           flags);
}

// RPC entrypoint for CallTraceService:AllocateBuffer().
boolean CallTraceService_AllocateBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out] */ CallTraceBuffer* call_trace_buffer) {
  // Delegate the call to the call trace service instance.
  return Service::Instance().AllocateBuffer(
      session_handle,
      call_trace_buffer);
}

// RPC entrypoint for CallTraceService::ExchangeBuffer().
boolean CallTraceService_ExchangeBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out][in] */ CallTraceBuffer* call_trace_buffer) {
  // Delegate the call to the call trace service instance.
  return Service::Instance().CommitAndExchangeBuffer(
      session_handle,
      call_trace_buffer,
      Service::PERFORM_EXCHANGE);
}

// RPC entrypoint for CallTraceService::ReturnBuffer().
boolean CallTraceService_ReturnBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out][in] */ CallTraceBuffer* call_trace_buffer) {
  // Delegate the call to the call trace service instance.
  return Service::Instance().CommitAndExchangeBuffer(
      session_handle,
      call_trace_buffer,
      Service::DO_NOT_PERFORM_EXCHANGE);
}

// RPC entrypoint for CallTraceService::CloseSession().
boolean CallTraceService_CloseSession(
    /* [out][in] */ SessionHandle* session_handle) {
  // Delegate the call to the call trace service instance.
  Service::Instance().CloseSession(session_handle);
  return true;
}

// RPC entrypoint for CallTraceControl::Stop().
boolean CallTraceService_Stop(/* [in] */ handle_t /* binding */) {
  // Delegate the call to the call trace service instance.
  return Service::Instance().RequestShutdown();
}

// This callback is invoked if the RPC mechanism detects that a client
// has ceased to exist, but the service still has resources allocated
// on the client's behalf.
void __RPC_USER SessionHandle_rundown(SessionHandle session_handle) {
  ignore_result(CallTraceService_CloseSession(&session_handle));
}
