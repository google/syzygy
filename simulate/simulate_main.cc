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
// of page-faults on them.

#include <objbase.h>
#include <iostream>
#include <set>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/string_number_conversions.h"
#include "syzygy/simulate/page_fault_simulation.h"
#include "syzygy/simulate/simulator.h"

namespace {

using simulate::Simulator;
using simulate::PageFaultSimulation;

const char kUsage[] =
    "Usage: simulate [options] [RPC log files ...]\n"
    "  Required Options:\n"
    "    --instrumented-dll=<path> the path to the instrumented DLL.\n"
    "  Optional Options:\n"
    "    --input-dll=<path> the input DLL from where the trace files belong.\n"
    "    --output-file=<path> the output file.\n"
    "    --pretty-print enables pretty printing of the JSON output file.\n"
    "    --pages-per-code-fault=INT The number of pages loaded by each\n"
    "        page-fault (default 8).\n"
    "    --page-size=INT the size of each page, in bytes (default 4KB).\n";

int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;
  return 1;
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
  typedef CommandLine::StringType StringType;
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

  int pages_per_code_fault = 0, page_size = 0;
  StringType pages_per_code_fault_str, page_size_str;
  pages_per_code_fault_str =
      cmd_line->GetSwitchValueNative("pages-per-code-fault");
  page_size_str = cmd_line->GetSwitchValueNative("page-size");

  if (!pages_per_code_fault_str.empty() &&
      !base::StringToInt(pages_per_code_fault_str, &pages_per_code_fault)) {
    return Usage("Invalid pages-per-code-fault value.");
  }
  if (!page_size_str.empty() &&
      !base::StringToInt(page_size_str, &page_size)) {
    return Usage("Invalid page-size value.");
  }

  PageFaultSimulation simulation;

  if (!pages_per_code_fault_str.empty())
    simulation.set_pages_per_code_fault(pages_per_code_fault);

  if (!page_size_str.empty())
    simulation.set_page_size(page_size);

  Simulator simulator(input_dll_path,
                      instrumented_dll_path,
                      trace_paths,
                      &simulation);

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
  if (!simulation.SerializeToJSON(output, pretty_print)) {
    LOG(ERROR) << "Unable to write JSON file.";
    return 1;
  }

  return 0;
}
