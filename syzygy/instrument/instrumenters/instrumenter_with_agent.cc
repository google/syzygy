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

#include "base/file_util.h"
#include "base/logging.h"
#include "syzygy/common/application.h"

namespace instrument {
namespace instrumenters {

bool InstrumenterWithAgent::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  // TODO(chrisha): Simplify the input/output image parsing once external
  //     tools have been updated.

  // Parse the input image.
  if (command_line->HasSwitch("input-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --input-dll.";
    input_dll_path_ = common::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("input-dll"));
  } else {
    input_dll_path_ = common::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("input-image"));
  }

  // Parse the output image.
  if (command_line->HasSwitch("output-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --output-dll.";
    output_dll_path_ = common::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("output-dll"));
  } else {
    output_dll_path_ = common::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("output-image"));
  }

  // Ensure that both input and output have been specified.
  if (input_dll_path_.empty() || output_dll_path_.empty()) {
    LOG(ERROR) << "You must provide input and output file names.";
    return false;
  }

  // Parse the remaining command line arguments.
  input_pdb_path_ = common::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = common::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("output-pdb"));
  allow_overwrite_ = command_line->HasSwitch("overwrite");
  debug_friendly_ = command_line->HasSwitch("debug-friendly");
  new_decomposer_ = command_line->HasSwitch("new-decomposer");
  no_augment_pdb_ = command_line->HasSwitch("no-augment-pdb");
  no_parse_debug_info_ = command_line->HasSwitch("no-parse-debug-info");
  no_strip_strings_ = command_line->HasSwitch("no-strip-strings");

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

  if (agent_dll_.empty()) {
    LOG(ERROR) << "No agent DLL has been specified.";
    return false;
  }

  if (!ParseAdditionalCommandLineArguments(command_line)) {
    LOG(ERROR) << "Unable to parse the additional arguments from the command "
               << "line.";
    return false;
  }

  return true;
}

bool InstrumenterWithAgent::Instrument() {
  pe::PERelinker* relinker = GetRelinker();
  DCHECK(relinker != NULL);
  relinker->set_input_path(input_dll_path_);
  relinker->set_input_pdb_path(input_pdb_path_);
  relinker->set_output_path(output_dll_path_);
  relinker->set_output_pdb_path(output_pdb_path_);
  relinker->set_allow_overwrite(allow_overwrite_);
  relinker->set_augment_pdb(!no_augment_pdb_);
  relinker->set_parse_debug_info(!no_parse_debug_info_);
  relinker->set_use_new_decomposer(new_decomposer_);
  relinker->set_strip_strings(!no_strip_strings_);

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker->Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return false;
  }

  // Do the actual instrumentation.
  if (!InstrumentImpl())
    return false;

  // We let the PERelinker use the implicit OriginalOrderer.
  if (!relinker->Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return false;
  }

  return true;
}

pe::PETransformPolicy* InstrumenterWithAgent::GetTransformPolicy() {
  if (policy_.get() == NULL) {
    policy_.reset(new pe::PETransformPolicy());
    CHECK(policy_.get() != NULL);
  }
  return policy_.get();
}

pe::PERelinker* InstrumenterWithAgent::GetRelinker() {
  if (relinker_.get() == NULL) {
    relinker_.reset(new pe::PERelinker(GetTransformPolicy()));
    CHECK(relinker_.get() != NULL);
  }
  return relinker_.get();
}

}  // namespace instrumenters
}  // namespace instrument
