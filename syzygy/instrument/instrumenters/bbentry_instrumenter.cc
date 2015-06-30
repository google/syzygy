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

#include "syzygy/instrument/instrumenters/bbentry_instrumenter.h"

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/application/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char BasicBlockEntryInstrumenter::kAgentDllBasicBlockEntry[] =
    "basic_block_entry_client.dll";

BasicBlockEntryInstrumenter::BasicBlockEntryInstrumenter()
    : inline_fast_path_(false) {
  agent_dll_ = kAgentDllBasicBlockEntry;
}

bool BasicBlockEntryInstrumenter::InstrumentPrepare() {
  return true;
}

bool BasicBlockEntryInstrumenter::InstrumentImpl() {
  bbentry_transform_.reset(
      new instrument::transforms::BasicBlockEntryHookTransform());
  bbentry_transform_->set_instrument_dll_name(agent_dll_);
  bbentry_transform_->set_inline_fast_path(inline_fast_path_);
  bbentry_transform_->set_src_ranges_for_thunks(debug_friendly_);
  if (!relinker_->AppendTransform(bbentry_transform_.get()))
    return false;

  add_bb_addr_stream_mutator_.reset(new
      instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
          bbentry_transform_->bb_ranges(),
          common::kBasicBlockRangesStreamName));
  if (!relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get()))
    return false;

  return true;
}

bool BasicBlockEntryInstrumenter::DoCommandLineParse(
    const base::CommandLine* command_line) {
  if (!Super::DoCommandLineParse(command_line))
    return false;

  // Parse the additional command line arguments.
  inline_fast_path_ = command_line->HasSwitch("inline-fast-path");

  return true;
}

}  // namespace instrumenters
}  // namespace instrument
