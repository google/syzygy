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

#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"

#include "base/logging.h"

namespace instrument {
namespace instrumenters {

bool InstrumenterWithAgent::DoCommandLineParse(
    const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  if (!agent_dll_.empty()) {
    LOG(INFO) << "Default agent DLL for " << InstrumentationMode() << " mode "
              << "is \"" << agent_dll_ << "\".";
  }

  // Parse the custom agent if one is specified.
  if (command_line->HasSwitch("agent")) {
    std::string new_agent_dll = command_line->GetSwitchValueASCII("agent");
    if (new_agent_dll != agent_dll_) {
      agent_dll_ = new_agent_dll;
      LOG(INFO) << "Using custom agent DLL \"" << agent_dll_ << "\".";
    }
  }

  return true;
}

bool InstrumenterWithAgent::CheckCommandLineParse(
    const base::CommandLine* command_line) {
  if (agent_dll_.empty()) {
    LOG(ERROR) << "No agent DLL has been specified.";
    return false;
  }

  return Super::CheckCommandLineParse(command_line);
}

}  // namespace instrumenters
}  // namespace instrument
