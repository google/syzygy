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
// Declares the basic block entry instrumenter.
#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_BBENTRY_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_BBENTRY_INSTRUMENTER_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"
#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class BasicBlockEntryInstrumenter : public InstrumenterWithAgent {
 public:
  typedef InstrumenterWithAgent Super;

  BasicBlockEntryInstrumenter();
  ~BasicBlockEntryInstrumenter() { }

 protected:
  // The name of the agent for this mode of instrumentation.
  static const char kAgentDllBasicBlockEntry[];

  // @name InstrumenterWithAgent overrides.
  // @{
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override { return "bbentry"; }
  // @}

  // @name Super overrides.
  // @{
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // @name Command-line parameters.
  // @{
  bool inline_fast_path_;
  // @}

  // The transform for this agent.
  std::unique_ptr<instrument::transforms::BasicBlockEntryHookTransform>
      bbentry_transform_;

  // The PDB mutator for this agent.
  std::unique_ptr<instrument::mutators::AddIndexedDataRangesStreamPdbMutator>
      add_bb_addr_stream_mutator_;
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_BBENTRY_INSTRUMENTER_H_
