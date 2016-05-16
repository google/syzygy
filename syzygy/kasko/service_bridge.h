// Copyright 2014 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_SERVICE_BRIDGE_H_
#define SYZYGY_KASKO_SERVICE_BRIDGE_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string16.h"

#include "syzygy/kasko/kasko_rpc.h"

namespace common {
namespace rpc {

class ScopedRpcInterfaceRegistration;

}  // namespace rpc
}  // namespace common

namespace kasko {

class Service;

// Establishes an RPC service that forwards requests for the Kasko interface to
// a Service implementation. The Service will be invoked on a worker thread.
//
// Only a single instance of this class may exist at a time in a given process.
class ServiceBridge {
 public:
  // Instantiates a ServiceBridge configured to use |protocol| and |endpoint|
  // and to forwards requests to |service|.
  ServiceBridge(const base::string16& protocol,
                const base::string16& endpoint,
                std::unique_ptr<Service> service);
  ~ServiceBridge();

  // Starts serving requests. Returns immediately. The return value indicates
  // whether the service successfully started.
  //
  // If Run() returns true you _must_ call Stop() before destroying the
  // ServiceBridge.
  bool Run();

  // Stops listening for new requests. Blocks until all in-process requests are
  // handled. It is harmless to call Stop() on a non-running ServiceBridge.
  void Stop();

 private:
  // Without the parentheses the '::' is associated with 'boolean'.
  friend boolean(::KaskoService_SendDiagnosticReport)(  // NOLINT
      handle_t IDL_handle,
      MinidumpRequest request);

  std::unique_ptr<common::rpc::ScopedRpcInterfaceRegistration>
      interface_registration_;
  std::unique_ptr<Service> service_;

  base::string16 protocol_;
  base::string16 endpoint_;
  bool running_;

  DISALLOW_COPY_AND_ASSIGN(ServiceBridge);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_SERVICE_BRIDGE_H_
