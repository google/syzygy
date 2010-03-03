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
#ifndef SAWBUCK_VIEWER_SAWBUCK_GUIDS_H_
#define SAWBUCK_VIEWER_SAWBUCK_GUIDS_H_


//
// SystemTraceControlGuid. Used to specify event tracing for kernel
//
DEFINE_GUID( /* 9e814aad-3204-11d2-9a82-006008a86939 */
    SystemTraceControlGuid,
    0x9e814aad,
    0x3204,
    0x11d2,
    0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39);

// {C43B1318-C63D-465b-BCF4-7A89A369F8ED}
DEFINE_GUID(kSawbuckLogProvider,
    0xc43b1318,
    0xc63d,
    0x465b,
    0xbc, 0xf4, 0x7a, 0x89, 0xa3, 0x69, 0xf8, 0xed);

#endif  // SAWBUCK_VIEWER_SAWBUCK_GUIDS_H_
