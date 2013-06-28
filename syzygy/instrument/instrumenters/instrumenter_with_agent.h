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
// Specialization of the instrumenter interface for the instrumenters who use an
// agent. This performs all the common bits of this kind of instrumenters:
//     - Parse the shared command-line parameters.
//     - Initialization the relinker.
//     - Default implementation of Instrument.
#ifndef  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
#define  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {

class InstrumenterWithAgent : public InstrumenterInterface {
 public:
  InstrumenterWithAgent()
      : allow_overwrite_(false),
        new_decomposer_(false),
        no_augment_pdb_(false),
        no_parse_debug_info_(false),
        no_strip_strings_(false) {
  }

  ~InstrumenterWithAgent() { }

  // @name InstrumenterInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line);
  virtual bool Instrument();
  // @}

  // @name Accessors.
  // @
  const std::string& agent_dll() {
    return agent_dll_;
  }
  // @}

 protected:
  // Template method that does the actual instrumentation for a given agent.
  // This function is meant to be called by the Instrument function.
  // @note The implementation should log on failure.
  virtual bool InstrumentImpl() = 0;

  // @name Internal machinery, replaceable for testing purposes.
  // @{
  virtual pe::PERelinker* GetRelinker();
  scoped_ptr<pe::PERelinker> relinker_;
  // @}

  // The agent DLL used by this instrumentation.
  std::string agent_dll_;

  // @name Command-line parameters.
  // @{
  base::FilePath input_dll_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_dll_path_;
  base::FilePath output_pdb_path_;
  bool allow_overwrite_;
  bool new_decomposer_;
  bool no_augment_pdb_;
  bool no_parse_debug_info_;
  bool no_strip_strings_;
  // @}
};

}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
