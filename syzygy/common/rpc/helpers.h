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

// Generic RPC call return structure. The ReturnType must be able to be
// initialized with a zero.
template<typename ReturnType>
struct RpcResult {
  RpcResult() : exception_occurred(FALSE), result(0) {}

  boolean exception_occurred;
  ReturnType result;

  bool succeeded() const {
    return exception_occurred == FALSE;
  }
};

// Specialization of RpcResult used by most RPC calls.
template<>
struct RpcResult<boolean> {
  RpcResult() : exception_occurred(FALSE), result(FALSE) {}

  boolean exception_occurred;
  boolean result;

  bool succeeded() const {
    return exception_occurred == FALSE && result == TRUE;
  }
};
using RpcStatus = RpcResult<boolean>;

// Helper to invoke an RPC function. Handles any number of paramters and auto
// infers the return type based on the function signature.
template<typename Func, typename ...Params>
RpcResult<decltype(std::declval<Func>()(std::declval<Params>()...))>
InvokeRpc(const Func& func, Params... params) {
  using ReturnType = decltype(std::declval<Func>()(std::declval<Params>()...));
  RpcResult<ReturnType> status;
  RpcTryExcept {
    status.result = func(params...);
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
  static_assert(
      sizeof(internal::dereference_pointer<RPC_WSTR>::value) == sizeof(T),
      "Type is incompatible.");
  return reinterpret_cast<RPC_WSTR>(value);
}

}  // namespace rpc
}  // namespace common

#endif  // SYZYGY_COMMON_RPC_HELPERS_H_
