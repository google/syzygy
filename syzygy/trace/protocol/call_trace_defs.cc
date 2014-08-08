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
// Definitions for call trace related objects common to the service and
// client libraries.

#include "syzygy/trace/protocol/call_trace_defs.h"

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"

// ETW Unique Identifiers.
const GUID kCallTraceProvider = {
    // {06255E36-14B0-4e57-8964-2E3D675A0E77}
    0x6255e36, 0x14b0, 0x4e57,
        { 0x89, 0x64, 0x2e, 0x3d, 0x67, 0x5a, 0xe, 0x77 } };
const GUID kCallTraceEventClass = {
    // {44CAEED0-5432-4c2d-96FA-CEC50C742F01}
    0x44caeed0, 0x5432, 0x4c2d,
        { 0x96, 0xfa, 0xce, 0xc5, 0xc, 0x74, 0x2f, 0x1 } };
const GUID kSystemTraceControlGuid =
    // {9E814AAD-3204-11D2-9A82-006008A86939}
    { 0x9e814aad, 0x3204, 0x11d2,
        { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

// ETW flags and options
const size_t kMinEtwBuffers = 15;
const size_t kMinEtwBuffersPerProcessor = 3;
const size_t kEtwBufferMultiplier = 5;
const int kDefaultEtwTraceFlags = 0;
const int kDefaultEtwKernelFlags = EVENT_TRACE_FLAG_PROCESS |
                                   EVENT_TRACE_FLAG_THREAD |
                                   EVENT_TRACE_FLAG_IMAGE_LOAD |
                                   EVENT_TRACE_FLAG_DISK_IO |
                                   EVENT_TRACE_FLAG_DISK_FILE_IO |
                                   EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS |
                                   EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS |
                                   EVENT_TRACE_FLAG_FILE_IO;

// Environment variable used for the RPC Instance ID suffix.
const char kSyzygyRpcInstanceIdEnvVar[] = "SYZYGY_RPC_INSTANCE_ID";
// Environment variable used to indicate that an RPC session is mandatory.
const char kSyzygyRpcSessionMandatoryEnvVar[] =
    "SYZYGY_RPC_SESSION_MANDATORY";

namespace {

// Default RPC protocol and endpoint.
const wchar_t* const kCallTraceRpcProtocol = L"ncalrpc";
const wchar_t* const kCallTraceRpcEndpoint = L"syzygy-call-trace-svc";
const wchar_t* const kCallTraceRpcMutex = L"syzygy-call-trace-svc-mutex";
const wchar_t* const kCallTraceRpcEvent = L"syzygy-call-trace-svc-event";

void MakeInstanceString(const base::StringPiece16& prefix,
                        const base::StringPiece16& id,
                        std::wstring* output) {
  DCHECK(output != NULL);
  DCHECK(!prefix.empty());

  output->assign(prefix.begin(), prefix.end());
  if (!id.empty()) {
    output->append(1, '-');
    output->append(id.begin(), id.end());
  }
}

}  // namespace

const TraceFileHeader::Signature TraceFileHeader::kSignatureValue = {
    'S', 'Z', 'G', 'Y' };

void GetSyzygyCallTraceRpcProtocol(std::wstring* protocol) {
  DCHECK(protocol != NULL);
  protocol->assign(kCallTraceRpcProtocol);
}

void GetSyzygyCallTraceRpcEndpoint(const base::StringPiece16& id,
                                   std::wstring* endpoint) {
  MakeInstanceString(kCallTraceRpcEndpoint, id, endpoint);
}

void GetSyzygyCallTraceRpcMutexName(const base::StringPiece16& id,
                                    std::wstring* mutex_name) {
  MakeInstanceString(kCallTraceRpcMutex, id, mutex_name);
}

void GetSyzygyCallTraceRpcEventName(const base::StringPiece16& id,
                                    std::wstring* event_name) {
  MakeInstanceString(kCallTraceRpcEvent, id, event_name);
}
