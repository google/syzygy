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

  // Read and decompose the input image for starters.
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path))
    return Usage("Unable to read input image");

  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL))
    return Usage("Unable to decompose input image");

  // Construct and initialize our instrumenter.
  Instrumenter instrumenter(decomposed.address_space, &decomposed.image);
  if (!instrumenter.Initialize(decomposed.header.nt_headers)) {
    return Usage("Unable to initialize instrumenter.");
  }

  // Copy the sections and the data directory.
  if (!instrumenter.CopySections()) {
    return Usage("Unable to copy sections.");
  }
  if (!instrumenter.CopyDataDirectory(decomposed.header)) {
    return Usage("Unable to copy the input image's data directory.");
  }

  // Instrument the binary.
  if (!instrumenter.AddCallTraceImportDescriptor(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT])) {
    return Usage("Unable to add call trace import.");
  }
  if (!instrumenter.InstrumentCodeBlocks(&decomposed.image)) {
    return Usage("Unable to instrument code blocks.");
  }

  // Finalize the headers and write the image.
  if (!instrumenter.FinalizeImageHeaders(decomposed.header)) {
    return Usage("Unable to finalize image headers.");
  }
  if (!instrumenter.WriteImage(output_dll_path)) {
    return Usage("Unable to write the ouput image.");
  }
}
