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
// Declares the entry thunk instrumenter.
#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_ENTRY_CALL_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_ENTRY_CALL_INSTRUMENTER_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/transforms/entry_call_transform.h"
#include "syzygy/instrument/transforms/thunk_import_references_transform.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class EntryCallInstrumenter : public InstrumenterWithAgent {
 public:
  typedef InstrumenterWithAgent Super;

  EntryCallInstrumenter();
  ~EntryCallInstrumenter() { }

 protected:
  // The name of the agents for the different mode of instrumentation.
  static const char kAgentDllProfile[];

  // @name InstrumenterWithAgent overrides.
  // @{
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override;
  // @}

  // @name Super overrides.
  // @{
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // @name Command-line parameters.
  // @{
  bool thunk_imports_;
  // @}

  // The transforms for this agent.
  std::unique_ptr<instrument::transforms::EntryCallTransform>
      entry_thunk_transform_;
  std::unique_ptr<instrument::transforms::ThunkImportReferencesTransform>
      import_thunk_tx_;
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_ENTRY_CALL_INSTRUMENTER_H_
