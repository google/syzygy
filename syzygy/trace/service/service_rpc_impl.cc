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

// This file implements the RPC stubs which bind the CallTraceService RPC
// handlers to a call trace Service instance.

#include "syzygy/trace/service/service_rpc_impl.h"

#include "syzygy/trace/service/service.h"

using trace::service::RpcServiceInstanceManager;
using trace::service::Service;

// The instance to which the RPC callbacks are bound.
Service* RpcServiceInstanceManager::instance_ = NULL;

// RPC entrypoint for CallTraceService::CreateSession().
boolean CallTraceService_CreateSession(
    /* [in] */ handle_t binding,
    /* [out] */ SessionHandle* session_handle,
    /* [out] */ CallTraceBuffer* call_trace_buffer,
    /* [out] */ unsigned long* flags) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->CreateSession(binding,
                                 session_handle,
                                 call_trace_buffer,
                                 flags);
}

// RPC entrypoint for CallTraceService:AllocateBuffer().
boolean CallTraceService_AllocateBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out] */ CallTraceBuffer* call_trace_buffer) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->AllocateBuffer(session_handle, call_trace_buffer);
}

// RPC entrypoint for CallTraceService:AllocateLargeBuffer().
boolean CallTraceService_AllocateLargeBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [in] */ unsigned long minimum_size,
    /* [out] */ CallTraceBuffer* call_trace_buffer) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->AllocateLargeBuffer(
      session_handle, minimum_size, call_trace_buffer);
}

// RPC entrypoint for CallTraceService::ExchangeBuffer().
boolean CallTraceService_ExchangeBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out][in] */ CallTraceBuffer* call_trace_buffer) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->CommitAndExchangeBuffer(session_handle,
                                           call_trace_buffer,
                                           Service::PERFORM_EXCHANGE);
}

// RPC entrypoint for CallTraceService::ReturnBuffer().
boolean CallTraceService_ReturnBuffer(
    /* [in] */ SessionHandle session_handle,
    /* [out][in] */ CallTraceBuffer* call_trace_buffer) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->CommitAndExchangeBuffer(session_handle,
                                           call_trace_buffer,
                                           Service::DO_NOT_PERFORM_EXCHANGE);
}

// RPC entrypoint for CallTraceService::CloseSession().
boolean CallTraceService_CloseSession(
    /* [out][in] */ SessionHandle* session_handle) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  ignore_result(instance->CloseSession(session_handle));
  return true;
}

// RPC entrypoint for CallTraceControl::Stop().
boolean CallTraceService_Stop(/* [in] */ handle_t /* binding */) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  return instance->RequestShutdown();
}

// This callback is invoked if the RPC mechanism detects that a client
// has ceased to exist, but the service still has resources allocated
// on the client's behalf.
void __RPC_USER SessionHandle_rundown(SessionHandle session_handle) {
  Service* instance = RpcServiceInstanceManager::GetInstance();
  ignore_result(instance->CloseSession(&session_handle));
}
