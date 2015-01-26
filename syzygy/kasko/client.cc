// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/client.h"

#include <Rpc.h>

#include <map>
#include <string>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/kasko_rpc.h"

namespace kasko {

Client::Client(const base::string16& endpoint) : endpoint_(endpoint) {
}

Client::~Client(){
}

void Client::SendReport(const EXCEPTION_POINTERS* exception_pointers,
                        const char* protobuf,
                        size_t protobuf_length,
                        const base::char16* const* keys,
                        const base::char16* const* values) const {
  // Establish the RPC binding.
  common::rpc::ScopedRpcBinding rpc_binding;
  if (!rpc_binding.Open(L"ncalrpc", endpoint_)) {
    LOG(ERROR) << "Failed to open an RPC binding.";
    return;
  }

  // Convert the crash keys to UTF-8.
  // TODO(erikwright): These values are repeatedly converted between UTF-8 and
  // UTF-16 between the initial client API invocation and the final HTTP upload.
  // A single encoding should be adopted from end to end.
  std::map<std::string, std::string> utf8_crash_keys;
  if (keys && values) {
    for (size_t i = 0; keys[i] && values[i]; ++i) {
      utf8_crash_keys[base::UTF16ToUTF8(keys[i])] =
          base::UTF16ToUTF8(values[i]);
    }
  }

  // Alias the crash key string buffers into the CrashKey array used for the RPC
  // invocation.
  scoped_ptr<CrashKey[]> crash_keys(new CrashKey[utf8_crash_keys.size()]);
  size_t index = 0;
  for (std::map<std::string, std::string>::const_iterator entry =
           utf8_crash_keys.begin();
       entry != utf8_crash_keys.end(); ++entry) {
    crash_keys[index].name =
        reinterpret_cast<const signed char*>(entry->first.c_str());
    crash_keys[index].value =
        reinterpret_cast<const signed char*>(entry->second.c_str());
    ++index;
  }
  DCHECK_EQ(index, utf8_crash_keys.size());

  // Invoke SendDiagnosticReport via RPC.
  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(),
      reinterpret_cast<unsigned long>(exception_pointers),
      base::PlatformThread::CurrentId(), protobuf_length,
      reinterpret_cast<const signed char*>(protobuf), utf8_crash_keys.size(),
      crash_keys.get());

  if (!status.succeeded())
    LOG(ERROR) << "Failed to send the crash report.";
}

}  // namespace kasko
