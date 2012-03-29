// Copyright 2012 Google Inc.
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
// Defines the InstrumentApp class, which implements the command-line
// "instrument" tool.

#ifndef SYZYGY_INSTRUMENT_INSTRUMENT_APP_H_
#define SYZYGY_INSTRUMENT_INSTRUMENT_APP_H_

#include "base/command_line.h"
#include "base/file_path.h"
#include "base/string_piece.h"
#include "base/time.h"
#include "syzygy/common/application.h"
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {

// Implements the "instrument" command-line application.
//
// Refer to kUsageFormatStr (referenced from InstrumentApp::Usage()) for
// usage information.
class InstrumentApp : public common::AppImplBase {
 public:

  InstrumentApp()
      : use_new_workflow_(false),
        instrument_interior_references_(true),
        allow_overwrite_(false),
        debug_friendly_(false) {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 protected:
  // @name Utility members.
  // @{
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;
  int InstrumentWithNewWorkflow();
  int InstrumentWithOldWorkflow();
  // @}

  // @name Command-line parameters.
  // @{
  FilePath input_dll_path_;
  FilePath input_pdb_path_;
  FilePath output_dll_path_;
  FilePath output_pdb_path_;
  std::string client_dll_;
  bool use_new_workflow_;
  bool instrument_interior_references_;
  bool allow_overwrite_;
  bool debug_friendly_;
  // @}

  // @name Internal machinery, replaceable for testing purposes.
  // @{
  virtual pe::PERelinker& GetRelinker();
  virtual Instrumenter& GetInstrumenter();
  scoped_ptr<pe::PERelinker> relinker_;
  scoped_ptr<Instrumenter> instrumenter_;
  // @}
};

}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENT_APP_H_
