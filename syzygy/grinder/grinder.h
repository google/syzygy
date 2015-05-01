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
// Declares the grinder interface. A grinder is broadly a ParseEventHandler
// that can parse a command-line, do a unit of work, and produce some summary
// output.
#ifndef SYZYGY_GRINDER_GRINDER_H_
#define SYZYGY_GRINDER_GRINDER_H_

#include "base/command_line.h"
#include "syzygy/trace/parse/parser.h"

namespace grinder {

// The simple interface all grinders implement.
class GrinderInterface : public trace::parser::ParseEventHandlerImpl {
 public:
  typedef trace::parser::Parser Parser;

  virtual ~GrinderInterface() { }

  // Parses any required and/or optional arguments from the command-line.
  // @param command_line the command-line to be parsed.
  // @returns true on success, false otherwise.
  // @note The implementation should log on failure.
  virtual bool ParseCommandLine(const base::CommandLine* command_line) = 0;

  // Provides a pointer to the parse engine that will be used to push events
  // to the grinder. This will be called after a successful call to
  // ParseCommandLine and prior to any parse event handling.
  // @param parser the parser that will be feeding events to this event
  //     handler.
  virtual void SetParser(Parser* parser) = 0;

  // Performs any computation/aggregation/summarization that needs to be done
  // after having parsed trace files. This will only be called after a
  // successful call to ParseCommandLine and after all parse events have been
  // successfully handled by this object.
  // @returns true on success, false otherwise.
  // @note The implementation should log on failure.
  virtual bool Grind() = 0;

  // Produces the final output to the provided file handle. This will only be
  // called after a successful call to Grind.
  // @returns true on success, false otherwise.
  // @note The implementation should log on failure.
  virtual bool OutputData(FILE* file) = 0;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDER_H_
