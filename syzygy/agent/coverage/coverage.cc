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
// Implementation of the code coverage DLL.
#include "syzygy/agent/coverage/coverage.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/lazy_instance.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/agent/common/scoped_last_error_keeper.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

extern "C" void __declspec(naked) _indirect_penter_dllmain() {
  __asm {
    // Stack: ..., ret_addr, freq_data, func_addr.

    // Stash volatile registers.
    push eax
    push ecx
    push edx
    pushfd

    // Stack: ..., ret_addr, freq_data, func_addr, eax, ecx, edx, fd.

    // Retrieve the address pushed by the calling thunk. This is the argument to
    // our entry hook.
    lea eax, DWORD PTR[esp + 0x10]
    push eax

    // Stack: ..., ret_addr, freq_data, func_addr, eax, ecx, edx, fd,
    //        &func_addr.

    call agent::coverage::Coverage::EntryHook

    // Stack: ..., ret_addr, freq_data, func_addr, eax, ecx, edx, fd.

    // Restore volatile registers.
    popfd
    pop edx
    pop ecx
    pop eax

    // Stack: ..., ret_addr, freq_data, func_addr.

    // Return to the address pushed by our calling thunk, func_addr. We make
    // sure to pop off the freq_data passed to us by the thunks.
    ret 4

    // Stack: ..., ret_addr.
  }
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  using agent::coverage::Coverage;

  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit;

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      DCHECK(at_exit == NULL);
      at_exit = new base::AtExitManager();

      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"coverage");
      LOG(INFO) << "Initialized coverage client library.";
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      DCHECK(at_exit != NULL);
      delete at_exit;
      at_exit = NULL;
      break;

    default:
      break;
  }

  return TRUE;
}

namespace agent {
namespace coverage {

namespace {

using agent::common::ScopedLastErrorKeeper;
using ::common::IndexedFrequencyData;
using ::common::kBasicBlockCoverageAgentId;
using ::common::kBasicBlockFrequencyDataVersion;

// All tracing runs through this object.
base::LazyInstance<agent::coverage::Coverage> static_coverage_instance =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

Coverage* Coverage::Instance() {
  return static_coverage_instance.Pointer();
}

Coverage::Coverage() {
  trace::client::InitializeRpcSession(&session_, &segment_);
}

Coverage::~Coverage() {
}

void WINAPI Coverage::EntryHook(EntryHookFrame* entry_frame) {
  DCHECK(entry_frame != NULL);

  ScopedLastErrorKeeper scoped_last_error_keeper;

  // Prevent repeated initializations. We don't log on this so as to keep the
  // spew down for processes that create lots of threads. The first entry to
  // this is under the loader lock, so we don't need to protect the write.
  // After that we are only ever reading the value.
  if (entry_frame->coverage_data->initialization_attempted != 0)
    return;
  entry_frame->coverage_data->initialization_attempted = 1;

  // Get the address of the module.
  void* module_base = NULL;
  if (!trace::client::GetModuleBaseAddress(entry_frame->coverage_data,
                                           &module_base)) {
    LOG(ERROR) << "Unable to get module base address.";
    return;
  }
  HMODULE module = reinterpret_cast<HMODULE>(module_base);

  // Get the coverage singleton.
  Coverage* coverage = Coverage::Instance();
  DCHECK(coverage != NULL);

  // If the call trace client is not running we simply abort. This is not an
  // error, however, as the instrumented module can still run.
  if (!coverage->session_.IsTracing()) {
    LOG(WARNING) << "Unable to initialize coverage client as we are not "
                 << "tracing.";
    return;
  }

  // Log the module. This is required in order to associate basic-block
  // frequency with a module and PDB file during post-processing.
  if (!agent::common::LogModule(module, &coverage->session_,
                                &coverage->segment_)) {
    LOG(ERROR) << "Failed to log module.";
    return;
  }

  // We immediately flush the segment containing the module data so that it
  // appears prior to the coverage data in the trace file. This makes parsing
  // easier. We exchange for another buffer so that if any other instrumented
  // modules use this same agent they are also able to log a module event.
  if (!coverage->session_.ExchangeBuffer(&coverage->segment_)) {
    LOG(ERROR) << "Failed to exchange module event buffer.";
    return;
  }

  // Initialize the coverage data for this module.
  if (!coverage->InitializeCoverageData(module_base,
                                        entry_frame->coverage_data)) {
    LOG(ERROR) << "Failed to initialize coverage data.";
    return;
  }

  LOG(INFO) << "Coverage client initialized.";
}

bool Coverage::InitializeCoverageData(void* module_base,
                                      IndexedFrequencyData* coverage_data) {
  DCHECK(coverage_data != NULL);

  // We can only handle this if it looks right.
  if (coverage_data->agent_id != kBasicBlockCoverageAgentId ||
      coverage_data->version != kBasicBlockFrequencyDataVersion ||
      coverage_data->frequency_size != 1U ||
      coverage_data->num_columns != 1U ||
      coverage_data->data_type != IndexedFrequencyData::COVERAGE) {
    LOG(ERROR) << "Unexpected values in the coverage data structures.";
    return false;
  }

  // Nothing to allocate? We're done!
  if (coverage_data->num_entries == 0) {
    LOG(WARNING) << "Module contains no instrumented basic blocks, not "
                 << "allocating coverage data segment.";
    return true;
  }

  // Determine the size of the basic block frequency struct.
  size_t bb_freq_size = sizeof(TraceIndexedFrequencyData) +
      coverage_data->num_entries * coverage_data->frequency_size - 1;

  // Determine the size of the buffer we need. We need room for the basic block
  // frequency struct plus a single RecordPrefix header.
  size_t segment_size = bb_freq_size + sizeof(RecordPrefix);

  // Allocate the actual segment for the coverage data.
  trace::client::TraceFileSegment coverage_segment;
  if (!session_.AllocateBuffer(segment_size, &coverage_segment)) {
    LOG(ERROR) << "Failed to allocate coverage data segment.";
    return false;
  }

  // Ensure it's big enough to allocation the basic-block frequency data
  // we want. This automatically accounts for the RecordPrefix overhead.
  if (!coverage_segment.CanAllocate(bb_freq_size)) {
    LOG(ERROR) << "Returned coverage data segment smaller than expected.";
    return false;
  }

  // Allocate the basic-block frequency data. We will leave this allocated and
  // let it get flushed during tear-down of the call-trace client.
  TraceIndexedFrequencyData* trace_coverage_data =
      reinterpret_cast<TraceIndexedFrequencyData*>(
          coverage_segment.AllocateTraceRecordImpl(
              TRACE_INDEXED_FREQUENCY,
              bb_freq_size));
  DCHECK(trace_coverage_data != NULL);

  // Initialize the coverage data struct.
  base::win::PEImage image(module_base);
  trace_coverage_data->data_type = coverage_data->data_type;
  const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();
  trace_coverage_data->module_base_addr =
      reinterpret_cast<ModuleAddr>(image.module());
  trace_coverage_data->module_base_size =
      nt_headers->OptionalHeader.SizeOfImage;
  trace_coverage_data->module_checksum = nt_headers->OptionalHeader.CheckSum;
  trace_coverage_data->module_time_date_stamp =
      nt_headers->FileHeader.TimeDateStamp;
  trace_coverage_data->frequency_size = 1;
  trace_coverage_data->num_columns = 1;
  trace_coverage_data->num_entries = coverage_data->num_entries;

  // Hook up the newly allocated buffer to the call-trace instrumentation.
  coverage_data->frequency_data =
      trace_coverage_data->frequency_data;

  return true;
}

}  // namespace coverage
}  // namespace agent
