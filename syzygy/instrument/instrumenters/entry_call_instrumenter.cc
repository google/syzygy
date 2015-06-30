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

#include "syzygy/instrument/instrumenters/entry_call_instrumenter.h"

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/application/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char EntryCallInstrumenter::kAgentDllProfile[] = "profile_client.dll";

EntryCallInstrumenter::EntryCallInstrumenter()
    : thunk_imports_(false) {
  agent_dll_ = kAgentDllProfile;
}

bool EntryCallInstrumenter::InstrumentPrepare() {
  return true;
}

bool EntryCallInstrumenter::InstrumentImpl() {
  entry_thunk_transform_.reset(
      new instrument::transforms::EntryCallTransform(debug_friendly_));
  entry_thunk_transform_->set_instrument_dll_name(agent_dll_);
  relinker_->AppendTransform(entry_thunk_transform_.get());

  // If we are thunking imports then add the appropriate transform.
  if (thunk_imports_) {
    import_thunk_tx_.reset(
        new instrument::transforms::ThunkImportReferencesTransform);
    // Use the selected client DLL.
    import_thunk_tx_->set_instrument_dll_name(agent_dll_);
    relinker_->AppendTransform(import_thunk_tx_.get());
  }

  return true;
}

bool EntryCallInstrumenter::DoCommandLineParse(
    const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  thunk_imports_ = command_line->HasSwitch("instrument-imports");

  return true;
}

const char* EntryCallInstrumenter::InstrumentationMode() {
  return "profile";
}

}  // namespace instrumenters
}  // namespace instrument
