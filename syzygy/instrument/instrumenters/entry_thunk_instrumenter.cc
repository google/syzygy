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

#include "syzygy/instrument/instrumenters/entry_thunk_instrumenter.h"

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/application/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char EntryThunkInstrumenter::kAgentDllProfile[] = "profile_client.dll";
const char EntryThunkInstrumenter::kAgentDllRpc[] = "call_trace_client.dll";

EntryThunkInstrumenter::EntryThunkInstrumenter(Mode instrumentation_mode)
    : instrumentation_mode_(instrumentation_mode),
      instrument_unsafe_references_(false),
      module_entry_only_(false),
      thunk_imports_(false) {
  DCHECK(instrumentation_mode != INVALID_MODE);
  switch (instrumentation_mode) {
    case CALL_TRACE:
      agent_dll_ = kAgentDllRpc;
      instrument_unsafe_references_ = true;
      module_entry_only_ = true;
      break;
    case PROFILE:
      agent_dll_ = kAgentDllProfile;
      instrument_unsafe_references_ = false;
      module_entry_only_ = false;
      break;
    default:
      NOTREACHED();
      break;
  }
}

bool EntryThunkInstrumenter::InstrumentPrepare() {
  return true;
}

bool EntryThunkInstrumenter::InstrumentImpl() {
  entry_thunk_transform_.reset(
      new instrument::transforms::EntryThunkTransform());
  entry_thunk_transform_->set_instrument_dll_name(agent_dll_);
  entry_thunk_transform_->set_instrument_unsafe_references(
      instrument_unsafe_references_);
  entry_thunk_transform_->set_src_ranges_for_thunks(debug_friendly_);
  entry_thunk_transform_->set_only_instrument_module_entry(module_entry_only_);
  if (!relinker_->AppendTransform(entry_thunk_transform_.get()))
    return false;

  // If we are thunking imports then add the appropriate transform.
  if (thunk_imports_) {
    import_thunk_tx_.reset(
        new instrument::transforms::ThunkImportReferencesTransform);
    // Use the selected client DLL.
    import_thunk_tx_->set_instrument_dll_name(agent_dll_);
    if (!relinker_->AppendTransform(import_thunk_tx_.get()))
      return false;
  }

  return true;
}

bool EntryThunkInstrumenter::DoCommandLineParse(
    const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  if (instrumentation_mode_ == CALL_TRACE) {
    module_entry_only_ = command_line->HasSwitch("module-entry-only");
    instrument_unsafe_references_ = !command_line->HasSwitch("no-unsafe-refs");
  }
  thunk_imports_ = command_line->HasSwitch("instrument-imports");

  return true;
}

const char* EntryThunkInstrumenter::InstrumentationMode() {
  switch (instrumentation_mode_) {
    case CALL_TRACE:
      return "call trace";
    case PROFILE:
      return "profile";
    default:
      NOTREACHED();
      return NULL;
  }
}

}  // namespace instrumenters
}  // namespace instrument
