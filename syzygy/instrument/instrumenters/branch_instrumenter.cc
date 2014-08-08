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

#include "syzygy/instrument/instrumenters/branch_instrumenter.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char BranchInstrumenter::kAgentDllBasicBlockEntry[] =
    "basic_block_entry_client.dll";
const uint32 kNumSlots = 4U;

BranchInstrumenter::BranchInstrumenter()
    : buffering_(false), fs_slot_(0U) {
  agent_dll_ = kAgentDllBasicBlockEntry;
}

bool BranchInstrumenter::InstrumentImpl() {
  branch_transform_.reset(
      new instrument::transforms::BranchHookTransform());
  branch_transform_->set_instrument_dll_name(agent_dll_);
  branch_transform_->set_buffering(buffering_);
  branch_transform_->set_fs_slot(fs_slot_);
  if (!relinker_->AppendTransform(branch_transform_.get()))
    return false;

  add_bb_addr_stream_mutator_.reset(new
      instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
          branch_transform_->bb_ranges(),
          common::kBasicBlockRangesStreamName));
  if (!relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get()))
    return false;

  return true;
}

bool BranchInstrumenter::ParseAdditionalCommandLineArguments(
    const CommandLine* command_line) {
  // Parse the additional command line arguments.
  buffering_ = command_line->HasSwitch("buffering");

  if (command_line->HasSwitch("fs-slot")) {
    std::string fs_slot_str = command_line->GetSwitchValueASCII("fs-slot");
    if (!base::StringToUint(fs_slot_str, &fs_slot_)) {
      LOG(ERROR) << "Unrecognized FS-slot: not a valid number.";
      return false;
    }
    if (fs_slot_ == 0 || fs_slot_ > kNumSlots) {
      LOG(ERROR) << "fs-slot must be from 1 to " << kNumSlots << ".";
      return false;
    }
  }
  return true;
}

}  // namespace instrumenters
}  // namespace instrument
