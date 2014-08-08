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
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "syzygy/common/application.h"
#include "syzygy/instrument/instrumenter.h"

namespace instrument {

// Implements the "instrument" command-line application.
//
// Refer to kUsageFormatStr (referenced from InstrumentApp::Usage()) for
// usage information.
class InstrumentApp : public common::AppImplBase {
 public:
  InstrumentApp()
      : common::AppImplBase("Instrumenter") {
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

  // The instrumenter we delegate to.
  scoped_ptr<InstrumenterInterface> instrumenter_;
};

}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENT_APP_H_
