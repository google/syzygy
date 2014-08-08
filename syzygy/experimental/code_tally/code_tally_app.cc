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

#include "syzygy/experimental/code_tally/code_tally_app.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pe/pe_file.h"

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "\n"
    "  Crawls the symbol information for an image file, and outputs a JSON\n"
    "  file with a tally of the source contributions. The tally is aggregated\n"
    "  by object file, function, and finally source file/line.\n"
    "  This allows generating accurate accounting of how much code is\n"
    "  contributed by individual object files, and/or which source\n"
    "  files/lines.\n"
    "\n"
    "Required parameters\n"
    "  --input-image=<image file>\n"
    "      The image file to process.\n"
    "Optional parameters\n"
    "  --input-pdb=<pdb file>\n"
    "      Optionally provide the location of the PDB symbol file for the\n"
    "      given image file. If not provided, the tool will attempt to find\n"
    "      the symbol file by searching the symbol path.\n"
    "  --output-file=<output file>\n"
    "      Optionally provide the name or path to the output file. If not\n"
    "      provided, output will be to standard out.\n"
    "  --pretty-print\n"
    "      If provided, the JSON output will be pretty printed.\n";

}  // namespace

void CodeTallyApp::PrintUsage(const base::FilePath& program,
                              const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool CodeTallyApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  input_image_ = cmd_line->GetSwitchValuePath("input-image");
  if (input_image_.empty()) {
    PrintUsage(cmd_line->GetProgram(),
               "Must specify '--input-image' parameter!");
    return false;
  }

  // If no output file is specified stdout will be used.
  output_file_ = cmd_line->GetSwitchValuePath("output-file");
  // If no input PDB is specified the default is to search for it.
  input_pdb_ = cmd_line->GetSwitchValuePath("input-pdb");

  // Check the pretty print flag.
  pretty_print_ = cmd_line->HasSwitch("pretty-print");

  return true;
}

int CodeTallyApp::Run() {
  // Output defaults to STDOUT.
  FILE* output_file = stdout;

  // If an output file is specified, make sure we close it on exit.
  base::ScopedFILE scoped_file;

  // Open the output file, if one is provided. This is done early so as to fail
  // fast on problems with the output file or path.
  if (!output_file_.empty()) {
    scoped_file.reset(base::OpenFile(output_file_, "w"));

    if (!scoped_file.get()) {
      LOG(ERROR) << "Unable to open output file '"
                 << output_file_.value()<< "'.";
      return 1;
    }

    output_file = scoped_file.get();
  }

  // Do the tally.
  CodeTally tally(input_image_);
  if (!tally.TallyLines(input_pdb_))
    return 1;

  // And write the output file.
  core::JSONFileWriter writer(output_file, pretty_print_);
  if (!tally.GenerateJsonOutput(&writer))
    return 1;

  return 0;
}

