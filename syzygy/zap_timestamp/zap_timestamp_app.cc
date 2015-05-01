// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/zap_timestamp/zap_timestamp_app.h"

#include "base/strings/string_number_conversions.h"

namespace zap_timestamp {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls --input-image=<PE file>\n"
    "\n"
    "  A tool that normalizes the GUID and timestamps associated with a\n"
    "  given PE/PDB file pair. The PDB files matching each given PE file can\n"
    "  be tracked down automatically.\n"
    "\n"
    "Options:\n"
    "  --input-pdb=<PDB path>\n"
    "    If specified then this PDB will be used as the matching PDB. Will\n"
    "    fail if the PDB and the PE file are not paired.\n"
    "  --no-write-image\n"
    "    If this is specified then the PE file will not be written.\n"
    "  --no-write-pdb\n"
    "    If this is specified then the PDB file will not be written. Has no\n"
    "    effect for a PE file with no paired PDB.\n"
    "  --output-image=<PE path>\n"
    "    Specifies the output image path. If not specified defaults to\n"
    "    writing the image in place.\n"
    "  --output-pdb=<PDB path>\n"
    "    Specifies the output PDB path. If this is not specified but\n"
    "    --output-image is, then will place the PDB alongside the output\n"
    "    image with the same basename. If this is specified then\n"
    "    --output-image must also be specified."
    "  --overwrite\n"
    "    If specified will allow overwriting of existing output files. Must\n"
    "    be specified for in place processing.\n"
    "  --timestamp-value=<seconds since Jan 1, 1970>\n"
    "    The timestamp value to use in the binaries, if not specified an\n"
    "    arbitrary date in the past will be used (default to Jan 1, 2010).\n";

void PrintUsage(FILE* out,
                const base::FilePath& program,
                const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out);
    ::fprintf(out, "\n\n");
  }

  ::fprintf(out, kUsageFormatStr, program.BaseName().value().c_str());
}

}  // namespace

bool ZapTimestampApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK(command_line != NULL);

  if (command_line->HasSwitch("help")) {
    PrintUsage(out(), command_line->GetProgram(), nullptr);
    return false;
  }

  base::FilePath path = command_line->GetSwitchValuePath("input-image");
  if (path.empty()) {
    PrintUsage(out(), command_line->GetProgram(),
               "You must specify --input-image.");
    return false;
  }
  zap_.set_input_image(path);

  zap_.set_input_pdb(command_line->GetSwitchValuePath("input-pdb"));
  zap_.set_output_image(command_line->GetSwitchValuePath("output-image"));
  zap_.set_output_pdb(command_line->GetSwitchValuePath("output-pdb"));
  zap_.set_write_image(!command_line->HasSwitch("no-write-image"));
  zap_.set_write_pdb(!command_line->HasSwitch("no-write-pdb"));
  zap_.set_overwrite(command_line->HasSwitch("overwrite"));

  if (command_line->HasSwitch("timestamp-value")) {
    size_t timestamp_value = 0;
    if (!base::StringToSizeT(
            command_line->GetSwitchValueASCII("timestamp-value"),
            &timestamp_value)) {
      LOG(ERROR) << "Unable to read the timestamp value from the command line.";
      return false;
    }
    zap_.set_timestamp_value(timestamp_value);
  }

  return true;
}

int ZapTimestampApp::Run() {
  if (!zap_.Init())
    return 1;

  if (!zap_.Zap())
    return 1;

  return 0;
}

}  // namespace zap_timestamp
