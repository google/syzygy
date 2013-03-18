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
// The runtime portion of a code coverage client. This is responsible for
// starting the RPC connection and initializing an array where the baked-in
// instrumentation will dump its code coverage results. The instrumentation
// injects a run-time dependency on this library and adds appropriate
// initialization hooks.

#ifndef SYZYGY_AGENT_COVERAGE_COVERAGE_H_
#define SYZYGY_AGENT_COVERAGE_COVERAGE_H_

#include <windows.h>
#include <winnt.h>
#include <vector>

#include "base/lazy_instance.h"
#include "base/win/pe_image.h"
#include "syzygy/agent/common/entry_frame.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/trace/client/rpc_session.h"

// Instrumentation stubs to handle the loading of the library.
extern "C" void _cdecl _indirect_penter_dllmain();

namespace agent {
namespace coverage {

// There's a single instance of this class.
class Coverage {
 public:
  // This is overlaid on a hand-crafted ASM generated stack frame. See
  // syzygy/agent/coverage/coverage.cc for details.
  struct EntryHookFrame {
    void* func_addr;
    common::IndexedFrequencyData* coverage_data;
  };

  // The thunks _indirect_penter_dllmain and _indirect_exe_entry are redirected
  // here.
  static void WINAPI EntryHook(EntryHookFrame* entry_frame);

  // Retrieves the coverage singleton instance.
  static Coverage* Instance();

 private:
  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<Coverage>;

  Coverage();
  ~Coverage();

  // Initializes the given coverage data element.
  bool InitializeCoverageData(void* module_base,
                              ::common::IndexedFrequencyData* coverage_data);

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // The trace file segment we're writing module events to. The coverage data
  // goes to specially allocated segments that we don't explicitly keep track
  // of, but rather that we let live until the client gets torn down.
  trace::client::TraceFileSegment segment_;
};

}  // namespace coverage
}  // namespace agent

#endif  // SYZYGY_AGENT_COVERAGE_COVERAGE_H_
