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
// Helper functions to wrap RPC invocations.

#ifndef SYZYGY_CALL_TRACE_RPC_HELPERS_H_
#define SYZYGY_CALL_TRACE_RPC_HELPERS_H_

#include "rpc.h"

// TODO(rogerm): Is there directly usable stuff in base/callback.h that
//     might make this simpler/cleaner?

namespace call_trace {
namespace client {

// Structure returned by RPC calls
struct RpcStatus {
  boolean exception_occurred;
  boolean result;

  bool succeeded() const {
    return exception_occurred == FALSE && result == TRUE;
  }
};

// Helper to invoke an RPC function taking one parameter.
template<typename Func, typename T1>
RpcStatus InvokeRpc(const Func& func, const T1& p1) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking two parameters.
template<typename Func, typename T1, typename T2>
RpcStatus InvokeRpc(const Func& func, const T1& p1, const T2& p2) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking three parameters.
template<typename Func, typename T1, typename T2, typename T3>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1, const T2& p2, const T3& p3) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking four parameters.
template<typename Func, typename T1, typename T2, typename T3, typename T4>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1, const T2& p2, const T3& p3, const T4& p4) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking five parameters.
template<typename Func,
         typename T1, typename T2, typename T3, typename T4, typename T5>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1, const T2& p2, const T3& p3, const T4& p4,
                    const T5& p5) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4, p5);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

}  // namespace call_trace::client
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_RPC_HELPERS_H_
