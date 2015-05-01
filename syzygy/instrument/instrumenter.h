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
// Declares the instrumenter interface.
#ifndef SYZYGY_INSTRUMENT_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTER_H_

#include "base/command_line.h"

namespace instrument {

// The simple interface all instrumenters implement.
class InstrumenterInterface {
 public:
  virtual ~InstrumenterInterface() { }

  // Parses any required and/or optional arguments from the command-line.
  // @param command_line the command-line to be parsed.
  // @returns true on success, false otherwise.
  virtual bool ParseCommandLine(const base::CommandLine* command_line) = 0;

  // Do the instrumentation.
  virtual bool Instrument() = 0;
};

}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTER_H_
