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
// Declares the branch instrumenter.
#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_BRANCH_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_BRANCH_INSTRUMENTER_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"
#include "syzygy/instrument/transforms/branch_hook_transform.h"

namespace instrument {
namespace instrumenters {

class BranchInstrumenter : public InstrumenterWithAgent {
 public:
  typedef InstrumenterWithAgent Super;

  BranchInstrumenter();
  ~BranchInstrumenter() { }

 protected:
  // The name of the agent for this mode of instrumentation.
  static const char kAgentDllBasicBlockEntry[];

  // @name InstrumenterWithAgent overrides.
  // @{
  bool InstrumentPrepare() override;
  bool InstrumentImpl();
  const char* InstrumentationMode() { return "branch"; }
  // @}

  // @name Super overrides.
  // @{
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // The transform for this agent.
  std::unique_ptr<instrument::transforms::BranchHookTransform>
      branch_transform_;

  // The PDB mutator for this agent.
  std::unique_ptr<instrument::mutators::AddIndexedDataRangesStreamPdbMutator>
      add_bb_addr_stream_mutator_;

  // @name Command-line parameters.
  // @{
  bool buffering_;
  uint32_t fs_slot_;
  // @}
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_BRANCH_INSTRUMENTER_H_
