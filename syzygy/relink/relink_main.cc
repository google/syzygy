// Copyright 2011 Google Inc.
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

#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging_win.h"
#include "syzygy/relink/relinker.h"

// {E6FF7BFB-34FE-42a3-8993-1F477DC36247}
const GUID kRelinkLogProviderName = { 0xe6ff7bfb, 0x34fe, 0x42a3,
    { 0x89, 0x93, 0x1f, 0x47, 0x7d, 0xc3, 0x62, 0x47 } };

static const char kUsage[] =
    "Usage: relink [options]\n"
    "  Required Options:\n"
    "    --input-dll=<path> the input DLL to relink\n"
    "    --input-pdb=<path> the PDB file associated with the input DLL\n"
    "    --output-dll=<path> the relinked output DLL\n"
    "    --output-pdb=<path> the rewritten PDB file for the output DLL\n"
    "  Optional Options:\n"
    "    --seed=<integer> provides a seed for the random reordering strategy\n"
    "    --order-file=<path> path to a JSON file containing the new order\n";

static int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }
  logging::LogEventProvider::Initialize(kRelinkLogProviderName);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath input_pdb_path = cmd_line->GetSwitchValuePath("input-pdb");
  FilePath output_dll_path = cmd_line->GetSwitchValuePath("output-dll");
  FilePath output_pdb_path = cmd_line->GetSwitchValuePath("output-pdb");
  FilePath order_file_path = cmd_line->GetSwitchValuePath("order-file");
  unsigned int seed = atoi(cmd_line->GetSwitchValueASCII("seed").c_str());

  if (input_dll_path.empty() || input_pdb_path.empty() ||
      output_dll_path.empty() || output_pdb_path.empty()) {
    return Usage("You must provide input and output file names.");
  }

  // Reorder the image, update the debug info and copy the data directory.
  if (!order_file_path.empty()) {
    if (!Relinker::Relink(input_dll_path,
                          input_pdb_path,
                          output_dll_path,
                          output_pdb_path,
                          order_file_path)) {
      return Usage("Unable to reorder the input image.");
    }
  } else {
    if (!Relinker::Relink(input_dll_path,
                          input_pdb_path,
                          output_dll_path,
                          output_pdb_path,
                          seed)) {
      return Usage("Unable randomly reorder the input image.");
    }
  }

  return 0;
}
