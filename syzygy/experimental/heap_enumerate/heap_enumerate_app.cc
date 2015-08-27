// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/heap_enumerate/heap_enumerate_app.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/experimental/heap_enumerate/heap_enumerate.h"
#include "syzygy/pe/pe_file.h"

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "\n"
    "  Allocates a heap with some blocks in it, then enumerates it and dumps\n"
    "  it to text.\n"
    "Optional parameters\n"
    "  --output-file=<output file>\n"
    "      Optionally provide the name or path to the output file. If not\n"
    "      provided, output will be to standard out.\n";

}  // namespace

void HeapEnumerateApp::PrintUsage(const base::FilePath& program,
                                  const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool HeapEnumerateApp::ParseCommandLine(const base::CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  // If no output file is specified stdout will be used.
  output_file_ = cmd_line->GetSwitchValuePath("output-file");

  return true;
}

int HeapEnumerateApp::Run() {
  // Output defaults to STDOUT.
  FILE* output_file = stdout;

  // If an output file is specified, make sure we close it on exit.
  base::ScopedFILE scoped_file;

  // Open the output file, if one is provided. This is done early so as to fail
  // fast on problems with the output file or path.
  if (!output_file_.empty()) {
    scoped_file.reset(base::OpenFile(output_file_, "w"));

    if (!scoped_file.get()) {
      LOG(ERROR) << "Unable to open output file '" << output_file_.value()
                 << "'.";
      return 1;
    }

    output_file = scoped_file.get();
  }

  HeapEnumerate enumerate;

  // And write the output file.
  enumerate.EnumerateHeap(output_file);

  return 0;
}
