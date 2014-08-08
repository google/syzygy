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
//
// Parses trace files from an RPC instrumented dll file, and reports the number
// of page-faults on them.

#include <objbase.h>
#include <iostream>
#include <set>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/strings/string_number_conversions.h"
#include "syzygy/simulate/heat_map_simulation.h"
#include "syzygy/simulate/page_fault_simulation.h"
#include "syzygy/simulate/simulator.h"

namespace {

using simulate::HeatMapSimulation;
using simulate::PageFaultSimulation;
using simulate::SimulationEventHandler;
using simulate::Simulator;

const char kUsage[] =
    "Usage: simulate [options] [RPC log files ...]\n"
    "  Required Options:\n"
    "    --instrumented-dll=<path> the path to the instrumented DLL.\n"
    "    --simulate-method=pagefault|heatmap what method used to simulate\n"
    "        the trace files.\n"
    "  Optional Options:\n"
    "    --pretty-print enables pretty printing of the JSON output file.\n"
    "    --input-dll=<path> the input DLL from where the trace files belong.\n"
    "    --output-file=<path> the output file.\n"
    "    For page fault method:\n"
    "      --pages-per-code-fault=INT The number of pages loaded by each\n"
    "          page-fault (default 8)\n"
    "      --page-size=INT the size of each page, in bytes (default 4KB).\n"
    "    For heat map method:\n"
    "      --time-slice-usecs=INT the size of each time slice in the heatmap,\n"
    "          in microseconds (default 1).\n"
    "      --memory-slice-bytes=INT the size of each memory slice,\n"
    "          in bytes (default 32KB).\n"
    "      --output-individual-functions Output information about each\n"
    "          function in each time/memory block\n";

int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  if (!logging::InitLogging(settings))
    return 1;

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  // Parse the command line.
  typedef CommandLine::StringType StringType;
  base::FilePath instrumented_dll_path =
      cmd_line->GetSwitchValuePath("instrumented-dll");
  base::FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  base::FilePath output_file_path = cmd_line->GetSwitchValuePath("output-file");
  bool pretty_print = cmd_line->HasSwitch("pretty-print");
  std::string simulate_method =
      cmd_line->GetSwitchValueASCII("simulate-method");

  std::vector<base::FilePath> trace_paths;
  for (size_t i = 0; i < cmd_line->GetArgs().size(); ++i)
    trace_paths.push_back(base::FilePath(cmd_line->GetArgs()[i]));

  if (instrumented_dll_path.empty())
    return Usage("You must specify instrumented-dll.");
  if (trace_paths.empty())
    return Usage("You must specify at least one trace file.");

  scoped_ptr<SimulationEventHandler> simulation;

  if (simulate_method == "pagefault") {
    PageFaultSimulation* page_fault_simulation = new PageFaultSimulation();
    DCHECK(page_fault_simulation != NULL);
    simulation.reset(page_fault_simulation);

    int page_size = 0;
    int pages_per_code_fault = 0;
    StringType page_size_str = cmd_line->GetSwitchValueNative("page-size");
    StringType pages_per_code_fault_str =
        cmd_line->GetSwitchValueNative("pages-per-code-fault");

    if (!page_size_str.empty()) {
      if (!base::StringToInt(page_size_str, &page_size))
        return Usage("Invalid page-size value.");
      else
        page_fault_simulation->set_page_size(page_size);
    }

    if (!pages_per_code_fault_str.empty()) {
      if (!base::StringToInt(pages_per_code_fault_str, &pages_per_code_fault))
        return Usage("Invalid pages-per-code-fault value.");
      else
        page_fault_simulation->set_pages_per_code_fault(pages_per_code_fault);
    }
  } else if (simulate_method == "heatmap") {
    HeatMapSimulation* heat_map_simulation = new HeatMapSimulation();
    DCHECK(heat_map_simulation != NULL);
    simulation.reset(heat_map_simulation);

    int time_slice_usecs = 0;
    int memory_slice_bytes = 0;
    StringType time_slice_usecs_str =
        cmd_line->GetSwitchValueNative("time-slice-usecs");
    StringType memory_slice_bytes_str =
        cmd_line->GetSwitchValueNative("memory-slice-bytes");

    if (!time_slice_usecs_str.empty()) {
      if (!base::StringToInt(time_slice_usecs_str, &time_slice_usecs))
        return Usage("Invalid time-slice-usecs value.");
      else
        heat_map_simulation->set_time_slice_usecs(time_slice_usecs);
    }

    if (!memory_slice_bytes_str.empty()) {
      if (!base::StringToInt(memory_slice_bytes_str, &memory_slice_bytes))
        return Usage("Invalid memory-slice-bytes value.");
      else
        heat_map_simulation->set_memory_slice_bytes(memory_slice_bytes);
    }

    heat_map_simulation->set_output_individual_functions(
        cmd_line->HasSwitch("output-individual-functions"));
  } else {
    return Usage("Invalid simulate-method value.");
  }


  Simulator simulator(input_dll_path,
                      instrumented_dll_path,
                      trace_paths,
                      simulation.get());

  LOG(INFO) << "Parsing trace files.";
  if (!simulator.ParseTraceFiles()) {
    LOG(ERROR) << "Could not parse trace files.";
    return 1;
  }

  base::ScopedFILE output_file;
  FILE* output = NULL;
  if (output_file_path.empty()) {
    output = stdout;
  } else {
    output_file.reset(base::OpenFile(output_file_path, "w"));
    output = output_file.get();

    if (output == NULL) {
      LOG(ERROR) << "Failed to open " << output_file_path.value()
          << " for writing.";
      return 1;
    }
  }

  LOG(INFO) << "Writing JSON file.";
  if (!simulation->SerializeToJSON(output, pretty_print)) {
    LOG(ERROR) << "Unable to write JSON file.";
    return 1;
  }

  return 0;
}
