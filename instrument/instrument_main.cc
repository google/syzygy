// Copyright 2010 Google Inc.
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
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"

using core::BlockGraph;
using pe::Decomposer;
using pe::PEFile;

static const char kUsage[] =
    "Usage: instrument [options]\n"
    "  Required Options:\n"
    "    --input-dll=<path> the input DLL to instrument\n"
    "    --output-dll=<path> the instrumented output DLL\n";

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

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath output_dll_path = cmd_line->GetSwitchValuePath("output-dll");

  if (input_dll_path.empty() || output_dll_path.empty())
    return Usage("You must provide input and output file names.");

  if (!Instrumenter::Instrument(input_dll_path, output_dll_path)) {
    LOG(ERROR)<< L"Failed to instrument " << input_dll_path.value().c_str();
    return 1;
  }

  return 0;
}
