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
//
// Parses a module and ETW trace files, generating an ordering of the
// blocks in the decomposed image.
#include <iostream>
#include <objbase.h>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/string_number_conversions.h"
#include "base/string_split.h"
#include "base/stringprintf.h"
#include "syzygy/reorder/comdat_order.h"
#include "syzygy/reorder/linear_order_generator.h"
#include "syzygy/reorder/random_order_generator.h"

using reorder::ComdatOrder;
using reorder::LinearOrderGenerator;
using reorder::RandomOrderGenerator;
using reorder::Reorderer;

static const char kUsage[] =
    "Usage: instrument [options] [ETW log files ...]\n"
    "  Required Options:\n"
    "    --input-dll=<path> the input DLL to reorder\n"
    "    --instrumented-dll=<path> the name of the instrumented DLL\n"
    "    --output-order=<path> the output file\n"
    "  Optional Options:\n"
    "    --seed=INT generates a random ordering; don't specify ETW log files\n"
    "    --pretty-print enables pretty printing of the JSON output file\n"
    "    --output-stats outputs estimated startup page faults pre- and post-\n"
    "        reordering.\n"
    "    --output-comdats=<path> an output file that will be populated\n"
    "        with an MS LINKER compatible COMDAT order file equivalent to\n"
    "        the generated ordering\n"
    "    --reorderer-flags=<comma separated reorderer flags>\n"
    "  Reorderer Flags:\n"
    "    reorder-data: causes data to be reordered\n";

const char kFlags[] = "reorderer-flags";
const char kOutputComdats[] = "output-comdats";

static int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

// Parses reorderer flags. Returns true on success, false otherwise. On
// failure, also outputs Usage with an error message.
static bool ParseReordererFlags(CommandLine* cmd_line,
                                Reorderer::Flags* flags) {
  DCHECK(cmd_line != NULL);
  DCHECK(flags != NULL);

  if (!cmd_line->HasSwitch(kFlags))
    return true;

  // These flags must be kept in sync with Reorderer::FlagsEnum.
  typedef std::map<std::string, Reorderer::FlagsEnum> FlagMap;
  FlagMap flag_map;
  flag_map["reorder-data"] = Reorderer::kFlagReorderData;

  std::vector<std::string> text_flags;
  base::SplitString(cmd_line->GetSwitchValueASCII(kFlags), ',', &text_flags);
  for (size_t i = 0; i < text_flags.size(); ++i) {
    if (text_flags[i].empty())
      continue;
    FlagMap::const_iterator it = flag_map.find(text_flags[i]);
    if (it == flag_map.end()) {
      std::string message = base::StringPrintf("Unknown reorderer flag: %s.",
                                               text_flags[i].c_str());
      Usage(message.c_str());
      return false;
    }
    *flags |= it->second;
  }

  return true;
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

  // Parse the command line.
  typedef CommandLine::StringType StringType;
  FilePath instrumented_dll_path =
      cmd_line->GetSwitchValuePath("instrumented-dll");
  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath output_order = cmd_line->GetSwitchValuePath("output-order");

  int seed = 0;
  StringType seed_str(cmd_line->GetSwitchValueNative("seed"));
  if (!seed_str.empty() && !base::StringToInt(seed_str, &seed)) {
    return Usage("Invalid seed value.");
  }

  std::vector<FilePath> trace_paths;
  for (size_t i = 0; i < cmd_line->args().size(); ++i)
    trace_paths.push_back(FilePath(cmd_line->args()[i]));
  bool pretty_print = cmd_line->HasSwitch("pretty-print");

  if (instrumented_dll_path.empty() || input_dll_path.empty() ||
          output_order.empty()) {
    return Usage("You must specify instrumented-dll, input-dll.");
  }

  if (seed_str.empty()) {
    if  (trace_paths.size() < 2) {
      return Usage("You must specify at least two ETW trace files (kernel and "
          "call_trace) if you are not generating a random ordering.");
    }
  } else {
    if (trace_paths.size() != 0) {
      return Usage("Do not specify ETW trace files when generating a random "
          "ordering.");
    }
  }

  Reorderer::Flags reorderer_flags = 0;
  if (!ParseReordererFlags(cmd_line, &reorderer_flags)) {
    return 1;
  }

  // Initialize COM, as it is used by Decomposer, ComdatOrder and Reorderer.
  if (FAILED(CoInitialize(NULL))) {
    LOG(ERROR) << "Failed to initialize COM.";
    return 1;
  }

  scoped_ptr<Reorderer::OrderGenerator> order_generator;
  if (!seed_str.empty()) {
    order_generator.reset(new RandomOrderGenerator(seed));
  } else {
    order_generator.reset(new LinearOrderGenerator());
  }

  pe::Decomposer::DecomposedImage decomposed;
  reorder::Reorderer::Order order(decomposed);
  Reorderer reorderer(input_dll_path,
                      instrumented_dll_path,
                      trace_paths,
                      reorderer_flags);
  if (!reorderer.Reorder(order_generator.get(), &order)) {
    LOG(ERROR) << "Reorder failed.";
    return 1;
  }

  if (cmd_line->HasSwitch("output-stats"))
    order.OutputFaultEstimates(stdout);

  if (!order.SerializeToJSON(output_order, pretty_print)) {
    LOG(ERROR) << "Unable to output order.";
    return 1;
  }

  // If requested, output the ordering as an MS LINKER compatible list of
  // COMDATs.
  if (cmd_line->HasSwitch(kOutputComdats)) {
    FilePath path = cmd_line->GetSwitchValuePath(kOutputComdats);
    ComdatOrder comdat_order(input_dll_path);
    if (!comdat_order.LoadSymbols()) {
      LOG(ERROR) << "Unable to load symbols.";
      return 1;
    }
    if (!comdat_order.OutputOrder(path, order)) {
      LOG(ERROR) << "Unable to output COMDAT order file.";
      return 1;
    }
  }

  CoUninitialize();

  return 0;
}
