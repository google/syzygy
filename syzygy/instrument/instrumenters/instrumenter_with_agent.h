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
// Specialization of the instrumenter interface for instrumenters that use an
// agent (and also the relinker).
#ifndef  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
#define  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_relinker.h"

namespace instrument {
namespace instrumenters {

class InstrumenterWithAgent : public InstrumenterWithRelinker {
 public:
  typedef InstrumenterWithRelinker Super;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BlockGraph::ImageFormat ImageFormat;

  InstrumenterWithAgent() { }
  ~InstrumenterWithAgent() { }

  // @name Accessors.
  // @
  const std::string& agent_dll() {
    return agent_dll_;
  }
  // @}

 protected:
  // @name InstrumenterWithRelinker interface redeclaration.
  // @{
  virtual bool InstrumentPrepare() = 0;
  virtual bool InstrumentImpl() = 0;
  virtual const char* InstrumentationMode() = 0;
  // @}

  // @name Super overrides.
  // @{
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  bool CheckCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // The agent DLL used by this instrumentation.
  std::string agent_dll_;

 private:
  DISALLOW_COPY_AND_ASSIGN(InstrumenterWithAgent);
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
