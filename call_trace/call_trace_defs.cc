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
// Definitions for call trace related objects common to the service and
// client libraries.

#include "syzygy/call_trace/call_trace_defs.h"

// {06255E36-14B0-4e57-8964-2E3D675A0E77}
const GUID kCallTraceProvider = {
    0x6255e36, 0x14b0, 0x4e57,
        { 0x89, 0x64, 0x2e, 0x3d, 0x67, 0x5a, 0xe, 0x77 } };

// {44CAEED0-5432-4c2d-96FA-CEC50C742F01}
const GUID kCallTraceEventClass = {
    0x44caeed0, 0x5432, 0x4c2d,
        { 0x96, 0xfa, 0xce, 0xc5, 0xc, 0x74, 0x2f, 0x1 } };

// RPC protocol and endpoint.
const wchar_t* const kCallTraceRpcProtocol = L"ncalrpc";
const wchar_t* const kCallTraceRpcEndpoint = L"syzygy-call-trace-svc";
const wchar_t* const kCallTraceRpcMutex = L"syzygy-call-trace-svc-mutex";

const TraceFileHeader::Signature TraceFileHeader::kSignatureValue = {
    'S', 'Z', 'G', 'Y' };
