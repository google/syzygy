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
  if (input_dll_path_.empty() || output_dll_path_.empty())
    return false;

  // Parse the remaining command line arguments.
  input_pdb_path_ = common::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = common::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("output-pdb"));
  allow_overwrite_ = command_line->HasSwitch("overwrite");
  new_decomposer_ = command_line->HasSwitch("new-decomposer");
  no_augment_pdb_ = command_line->HasSwitch("no-augment-pdb");
  no_parse_debug_info_ = command_line->HasSwitch("no-parse-debug-info");
  no_strip_strings_ = command_line->HasSwitch("no-strip-strings");

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

pe::PERelinker* InstrumenterWithAgent::GetRelinker() {
  if (relinker_.get() == NULL) {
    relinker_.reset(new pe::PERelinker());
    CHECK(relinker_.get() != NULL);
  }
  return relinker_.get();
}

}  // namespace instrument
