// Copyright 2012 Google Inc. All Rights Reserved.
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
#include "base/string_piece.h"
#include "base/time.h"
#include "base/files/file_path.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {

// Implements the "instrument" command-line application.
//
// Refer to kUsageFormatStr (referenced from InstrumentApp::Usage()) for
// usage information.
class InstrumentApp : public common::AppImplBase {
 public:

  // A list of known clients libraries.
  static const char kAgentDllAsan[];
  static const char kAgentDllBasicBlockEntry[];
  static const char kAgentDllCoverage[];
  static const char kAgentDllProfile[];
  static const char kAgentDllRpc[];

  // The mode of the instrumenter.
  enum Mode {
    kInstrumentInvalidMode,
    kInstrumentAsanMode,
    kInstrumentBasicBlockEntryMode,
    kInstrumentCallTraceMode,
    kInstrumentCoverageMode,
    kInstrumentProfileMode,
  };

  InstrumentApp()
      : common::AppImplBase("Instrumenter"),
        mode_(kInstrumentInvalidMode),
        allow_overwrite_(false),
        new_decomposer_(false),
        no_augment_pdb_(false),
        no_parse_debug_info_(false),
        no_strip_strings_(false),
        debug_friendly_(false),
        instrument_unsafe_references_(true),
        module_entry_only_(false),
        use_liveness_analysis_(false),
        remove_redundant_checks_(false),
        inline_fast_path_(false) {
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
  // @}

  // Used to parse old-style deprecated command-lines.
  // TODO(chrisha): Remove this once build scripts and profiling tools have
  //     been updated.
  void ParseDeprecatedMode(const CommandLine* command_line);

  // The mode of the instrumenter. This is valid after a successful call to
  // ParseCommandLine.
  Mode mode_;

  // @name Command-line parameters.
  // @{
  base::FilePath input_dll_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_dll_path_;
  base::FilePath output_pdb_path_;
  base::FilePath filter_path_;
  std::string agent_dll_;
  bool allow_overwrite_;
  bool new_decomposer_;
  bool no_augment_pdb_;
  bool no_parse_debug_info_;
  bool no_strip_strings_;
  bool debug_friendly_;
  bool thunk_imports_;
  bool instrument_unsafe_references_;
  bool module_entry_only_;
  bool use_liveness_analysis_;
  bool remove_redundant_checks_;
  bool inline_fast_path_;
  // @}

  // @name Internal machinery, replaceable for testing purposes.
  // @{
  virtual pe::PERelinker& GetRelinker();
  scoped_ptr<pe::PERelinker> relinker_;
  // @}
};

}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENT_APP_H_
