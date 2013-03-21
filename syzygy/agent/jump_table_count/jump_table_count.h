// Copyright 2013 Google Inc. All Rights Reserved.
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
// The runtime portion of a jump table entry count agent.

#ifndef SYZYGY_AGENT_JUMP_TABLE_COUNT_JUMP_TABLE_COUNT_H_
#define SYZYGY_AGENT_JUMP_TABLE_COUNT_JUMP_TABLE_COUNT_H_

#include <windows.h>

// Instrumentation stub to handle entry to a jump table case.
extern "C" void _cdecl _jump_table_case_counter();

// Instrumentation stub to handle the invocation of a DllMain-like entry point.
extern "C" void _cdecl _indirect_penter_dllmain();

#endif  // SYZYGY_AGENT_JUMP_TABLE_COUNT_JUMP_TABLE_COUNT_H_
