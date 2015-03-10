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
// Helper functions to wrap RPC invocations.

#ifndef SYZYGY_COMMON_RPC_HELPERS_H_
#define SYZYGY_COMMON_RPC_HELPERS_H_

#include <rpc.h>
#include <wtypes.h>

#include "base/macros.h"
#include "base/process/process_handle.h"
#include "base/strings/string_piece.h"

// TODO(rogerm): Is there directly usable stuff in base/callback.h that
//     might make this simpler/cleaner?

namespace common {
namespace rpc {

// Create an RPC binding.
//
// @param protocol The RPC protocol to bind.
// @param endpoint The endpoint/address to bind.
// @param out_handle A handle to the rpc binding will be returned here.
//
// @returns true on success.
bool CreateRpcBinding(const base::StringPiece16& protocol,
                      const base::StringPiece16& endpoint,
                      handle_t* out_handle);

// Retrieves the PID for the RPC client process.
//
// @param binding An RPC binding.
// @returns The client PID on success, or 0.
base::ProcessId GetClientProcessID(handle_t binding);

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
    status.result = func(p1, p2, p3);
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

// Helper to invoke an RPC function taking six parameters.
template <typename Func,
          typename T1,
          typename T2,
          typename T3,
          typename T4,
          typename T5,
          typename T6>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1,
                    const T2& p2,
                    const T3& p3,
                    const T4& p4,
                    const T5& p5,
                    const T6& p6) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4, p5, p6);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking seven parameters.
template <typename Func,
          typename T1,
          typename T2,
          typename T3,
          typename T4,
          typename T5,
          typename T6,
          typename T7>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1,
                    const T2& p2,
                    const T3& p3,
                    const T4& p4,
                    const T5& p5,
                    const T6& p6,
                    const T7& p7) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4, p5, p6, p7);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// Helper to invoke an RPC function taking eight parameters.
template <typename Func,
          typename T1,
          typename T2,
          typename T3,
          typename T4,
          typename T5,
          typename T6,
          typename T7,
          typename T8>
RpcStatus InvokeRpc(const Func& func,
                    const T1& p1,
                    const T2& p2,
                    const T3& p3,
                    const T4& p4,
                    const T5& p5,
                    const T6& p6,
                    const T7& p7,
                    const T8& p8) {
  RpcStatus status = { FALSE, FALSE };
  RpcTryExcept {
    status.result = func(p1, p2, p3, p4, p5, p6, p7, p8);
  } RpcExcept(1) {
    status.exception_occurred = TRUE;
  } RpcEndExcept;
  return status;
}

// A helper function to get an @p instance_id specialized version of the
// given @p root string.
std::wstring GetInstanceString(const base::StringPiece16& root,
                               const base::StringPiece16& instance_id);

// A helper class to manage an RPC binding handle.
class ScopedRpcBinding {
 public:
  ScopedRpcBinding();
  ~ScopedRpcBinding();

  // @returns the underlying RPC handle.
  handle_t Get() const { return rpc_binding_; }

  // Opens an RPC connection to @p endpoint using @p protocol.
  bool Open(const base::StringPiece16& protocol,
            const base::StringPiece16& endpoint);

  // Closes this RPC connection.
  bool Close();

 protected:
  // The OS level binding to the RPC layer.
  handle_t rpc_binding_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ScopedRpcBinding);
};

// A helper to manage an RPC interface registration.
class ScopedRpcInterfaceRegistration {
 public:
  explicit ScopedRpcInterfaceRegistration(RPC_IF_HANDLE if_spec);
  ~ScopedRpcInterfaceRegistration();

  RPC_STATUS status() { return status_; }

 private:
  RPC_IF_HANDLE if_spec_;
  RPC_STATUS status_;
};

namespace internal {

template <class T>
struct dereference_pointer;

template <class T>
struct dereference_pointer<T*> {
  typedef T value;
};

}  // namespace internal

template <class T>
RPC_WSTR AsRpcWstr(T* value) {
  COMPILE_ASSERT(
      sizeof(internal::dereference_pointer<RPC_WSTR>::value) == sizeof(T),
      TypeIsCompatible);
  return reinterpret_cast<RPC_WSTR>(value);
}

}  // namespace rpc
}  // namespace common

#endif  // SYZYGY_COMMON_RPC_HELPERS_H_
