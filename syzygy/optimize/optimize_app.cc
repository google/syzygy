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

#include "syzygy/optimize/optimize_app.h"

namespace optimize {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "  Required Options:\n"
    "    --input-image=<path>  The input image file to optimize.\n"
    "    --output-image=<path> Output path for the rewritten image file.\n"
    "  Options:\n"
    "    --branch-file=<path>  Branch statistics in JSON format.\n"
    "    --input-pdb=<path>    The PDB file associated with the input DLL.\n"
    "                          Default is inferred from input-image.\n"
    "    --output-pdb=<path>   Output path for the rewritten PDB file.\n"
    "                          Default is inferred from output-image.\n"
    "    --overwrite           Allow output files to be overwritten.\n"
    "\n";

}  // namespace

bool OptimizeApp::ParseCommandLine(const CommandLine* cmd_line) {

  if (cmd_line->HasSwitch("help"))
     return Usage(cmd_line, "");

  input_image_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-image"));
  output_image_path_ = cmd_line->GetSwitchValuePath("output-image");
  input_pdb_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = cmd_line->GetSwitchValuePath("output-pdb");
  branch_file_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("branch-file"));

  overwrite_ = cmd_line->HasSwitch("overwrite");

  // The --input-image argument is required.
  if (input_image_path_.empty())
    return Usage(cmd_line, "You must specify --input-image.");

  // The --output-image argument is required.
  if (output_image_path_.empty())
    return Usage(cmd_line, "You must specify --output-image.");

  return true;
}

bool OptimizeApp::SetUp() {
  // TODO(etienneb) implement this.
  return true;
}

int OptimizeApp::Run() {
  // TODO(etienneb) implement this.
  return 0;
}

bool OptimizeApp::Usage(const CommandLine* cmd_line,
                        const base::StringPiece& message) const {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), err());
    ::fprintf(err(), "\n\n");
  }

  ::fprintf(err(),
            kUsageFormatStr,
            cmd_line->GetProgram().BaseName().value().c_str());

  return false;
}

}  // namespace optimize
