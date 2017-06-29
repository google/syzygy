// Copyright 2017 Google Inc. All Rights Reserved.
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
// Declare the AFL instrumenter.

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_AFL_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_AFL_INSTRUMENTER_H_

#include <string>
#include <unordered_set>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/mutators/add_indexed_data_ranges_stream.h"
#include "syzygy/instrument/transforms/afl_transform.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class AFLInstrumenter : public InstrumenterWithRelinker {
 public:
  typedef InstrumenterWithRelinker Super;

  AFLInstrumenter() : Super() {}

  // From InstrumenterWithRelinker
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override;
  bool DoCommandLineParse(const base::CommandLine* command_line) override;

 protected:
  // Force decomposition flag.
  bool force_decomposition_;

  // Thread-safe instrumentation flag.
  bool multithread_mode_;

  // Store the whitelist / blacklist of functions to instrument or not.
  std::unordered_set<std::string> target_set_;
  bool whitelist_mode_;

  // Path to the JSON describing the instrumentation properties.
  base::FilePath config_path_;

  // Cookie check hook flag.
  bool cookie_check_hook_;

  // The transform for this agent.
  std::unique_ptr<instrument::transforms::AFLTransform> transformer_;

  // The PDB mutator for this agent.
  std::unique_ptr<instrument::mutators::AddIndexedDataRangesStreamPdbMutator>
      add_bb_addr_stream_mutator_;

 private:
  // Helper routines to read the JSON configuration file.
  bool ReadFromJSON(const std::string& json);
  bool ReadFromJSONPath(const base::FilePath& path);

  DISALLOW_COPY_AND_ASSIGN(AFLInstrumenter);
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_AFL_INSTRUMENTER_H_
