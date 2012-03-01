// Copyright 2012 Google Inc.
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
// Parses trace files from an RPC instrumented dll file, and reports the number
// of pagefaults on them.

#include <objbase.h>
#include <iostream>
#include <set>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/string_number_conversions.h"
#include "base/string_split.h"
#include "base/stringprintf.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/simulate/simulator.h"

namespace {

using simulate::Simulator;

const char kUsage[] =
    "Usage: simulate [options] RPC log files ...\n"
    "  Required Options:\n"
    "    --instrumented-dll=<path> the path to the instrumented DLL.\n"
    "  Optional Options:\n"
    "    --input-dll=<path> the input DLL from where the trace files belong.\n"
    "    --output-file=<path> the output file.\n"
    "    --pretty-print enables pretty printing of the JSON output file.\n";

int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;
  return 1;
}

// Serializes the data of a simulator to JSON.
// The serialization consists of a single dictionary containing
// the block number of each block that pagefaulted.
// @param simulator The simulator to be used.
// @param output The output FILE.
// @param pretty_print Pretty printing on the JSON file.
// @returns true on success, false on failure.
bool SerializeToJSON(const Simulator& simulator,
                     FILE* output,
                     bool pretty_print) {
  core::JSONFileWriter json_file(output, pretty_print);

  if (!json_file.OpenDict() ||
      !json_file.OutputKey("Pagefaults") ||
      !json_file.OpenList()) {
    return false;
  }

  Simulator::PageFaultSet::const_iterator i = simulator.page_faults().begin();
  for (; i != simulator.page_faults().end(); i++) {
    if (!json_file.OutputInteger(*i)) {
      return false;
    }
  }

  if (!json_file.CloseList() ||
      !json_file.CloseDict()) {
    return false;
  }

  return true;
}

} // namespace

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

  // Parse the command line.
  FilePath instrumented_dll_path =
      cmd_line->GetSwitchValuePath("instrumented-dll");
  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath output_file_path = cmd_line->GetSwitchValuePath("output-file");
  bool pretty_print = cmd_line->HasSwitch("pretty-print");

  std::vector<FilePath> trace_paths;
  for (size_t i = 0; i < cmd_line->GetArgs().size(); ++i)
    trace_paths.push_back(FilePath(cmd_line->GetArgs()[i]));

  if (instrumented_dll_path.empty())
    return Usage("You must specify instrumented-dll.");

  if (trace_paths.empty())
    return Usage("You must specify at least one trace file.");

  Simulator simulator(input_dll_path,
                      instrumented_dll_path,
                      trace_paths);

  LOG(INFO) << "Parsing trace files.";
  if (!simulator.ParseTraceFiles()) {
    LOG(ERROR) << "Could not parse trace files.";
    return 1;
  }

  file_util::ScopedFILE output_file;
  FILE* output = NULL;
  if (output_file_path.empty()) {
    output = stdout;
  } else {
    output_file.reset(file_util::OpenFile(output_file_path, "w"));
    output = output_file.get();

    if (output == NULL) {
      LOG(ERROR) << "Failed to open " << output_file_path.value()
          << " for writing.";
      return 1;
    }
  }

  LOG(INFO) << "Writing JSON file.";
  if (!SerializeToJSON(simulator, output, pretty_print)) {
    LOG(ERROR) << "Unable to write JSON file.";
    return 1;
  }

  return 0;
}
