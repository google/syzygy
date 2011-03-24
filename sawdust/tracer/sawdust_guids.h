// Copyright 2009 Google Inc.
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
#ifndef SAWDUST_TRACER_SAWDUST_GUIDS_H_
#define SAWDUST_TRACER_SAWDUST_GUIDS_H_

// SystemTraceControlGuid. Used to specify event tracing for kernel.
// {9E814AAD-3204-11D2-9A82-006008A86939}
DEFINE_GUID(
    SystemTraceControlGuid,
    0x9e814aad,
    0x3204,
    0x11d2,
    0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39);

// {C1E07480-EAC1-478f-9104-17DF313E0A7E}
DEFINE_GUID(
    kSawdustLoggingGuid,
    0xc1e07480,
    0xeac1,
    0x478f,
    0x91, 0x4, 0x17, 0xdf, 0x31, 0x3e, 0xa, 0x7e);


#endif  // SAWDUST_TRACER_SAWDUST_GUIDS_H_
