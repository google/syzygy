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

#include "syzygy/pdbfind/pdbfind_app.h"

#include "base/file_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_file.h"

namespace pdbfind {

namespace {

// The usage message must be kept in sync with the return codes below.
const int kSuccess = 0;
const int kError = 1;
const int kUnableToFindPdb = 2;
const int kMissingOrMalformedCodeViewRecord = 3;

const char kUsageFormatStr[] =
    "Usage: %ls <input-image-path>\n"
    "\n"
    "  Searches for the PDB file matching the provided image. If successfully\n"
    "  found prints the absolute path to stdout and exit with a return code\n"
    "  of 0.\n"
    "\n"
    "  On any error (invalid command line, missing image file) exits with an\n"
    "  error message and exits with a return code of 1.\n"
    "\n"
    "  If the PDB file is not found but the image contains a CodeView record\n"
    "  outputs the expected path to the PDB and exits with a return code of\n"
    "  2.\n"
    "\n"
    "  If the image does not contain a CodeView record or it is malformed\n"
    "  exits with a return code of 3.\n"
    "\n";

}  // namespace

bool PdbFindApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help"))
    return Usage(cmd_line, "");

  CommandLine::StringVector args = cmd_line->GetArgs();
  if (args.size() == 0)
    return Usage(cmd_line, "Must specify input-image-path.");

  if (args.size() > 1)
    return Usage(cmd_line, "Can specify only one input-image-path.");

  input_image_path_ = base::FilePath(args[0]);

  return true;
}

int PdbFindApp::Run() {
  if (!base::PathExists(input_image_path_)) {
    LOG(ERROR) << "File not found: " << input_image_path_.value();
    return kError;
  }

  pe::PEFile pe_file;
  if (!pe_file.Init(input_image_path_)) {
    LOG(ERROR) << "Failed to parse PE file: " << input_image_path_.value();
    return kError;
  }

  // Malformed or missing CodeView record.
  pe::PdbInfo pdb_info;
  if (!pdb_info.Init(pe_file))
    return kMissingOrMalformedCodeViewRecord;

  // Look for the matching PDB.
  base::FilePath pdb_path;
  if (!pe::FindPdbForModule(input_image_path_, &pdb_path)) {
    LOG(ERROR) << "Error searching for PDB file.";
    return kError;
  }

  // Not found? Then output the path where we expected to find it and indicate
  // that it could not be found.
  if (pdb_path.empty()) {
    fprintf(out(), "%ls\n", pdb_info.pdb_file_name().value().c_str());
    return kUnableToFindPdb;
  }

  fprintf(out(), "%ls\n", pdb_path.value().c_str());
  return kSuccess;
}

bool PdbFindApp::Usage(const CommandLine* cmd_line,
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

}  // namespace pdbfind
