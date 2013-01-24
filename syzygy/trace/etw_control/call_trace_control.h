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
#ifndef SYZYGY_TRACE_ETW_CONTROL_CALL_TRACE_CONTROL_H_
#define SYZYGY_TRACE_ETW_CONTROL_CALL_TRACE_CONTROL_H_

#include <windows.h>

// The following is part of the API exported by call_trace.dll.
extern "C" {

void CALLBACK StartCallTrace(HWND unused_window,
                             HINSTANCE unused_instance,
                             LPSTR unused_cmd_line,
                             int unused_show);

void CALLBACK StopCallTrace(HWND unused_window,
                            HINSTANCE unused_instance,
                            LPSTR unused_cmd_line,
                            int unused_show);

}  // extern "C"

// These are used by call_trace_control.exe
bool StartCallTraceImpl();
bool QueryCallTraceImpl();
bool StopCallTraceImpl();

#endif  // SYZYGY_TRACE_ETW_CONTROL_CALL_TRACE_CONTROL_H_
