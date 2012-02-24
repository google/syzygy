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

#include <algorithm>
#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/string_util.h"
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/reorder/orderers/explicit_orderer.h"

namespace {

using block_graph::BlockGraph;
using instrument::Instrumenter;
using pe::Decomposer;
using pe::PEFile;

static const char kUsage[] =
    "Usage: instrument [options]\n"
    "  Required Options:\n"
    "    --input-dll=<path>  The input DLL to instrument.\n"
    "    --output-dll=<path> The instrumented output DLL.\n"
    "\n"
    "  Options:\n"
    "    --input-pdb=<path>  The PDB for the DLL to instrument. If not\n"
    "                        explicitly provided will be searched for.\n"
    "    --output-pdb=<path> The PDB for the instrumented DLL. Defaults to\n"
    "                        the value of output-dll with the extension\n"
    "                        replaced by \".pdb\".\n"
    "    --call-trace-client=ETW|RPC|PROFILER|<other.dll>\n"
    "                        The call-trace client DLL to reference in the\n"
    "                        instrumented binary. The default value is ETW,\n"
    "                        which maps to the ETW based call-trace client.\n"
    "                        The value RPC maps to the RPC based call-trace\n"
    "                        client. The value PROFILER maps to the profiler\n"
    "                        client. You may also specify the name of any\n"
    "                        DLL which implements the call trace client\n"
    "                        interface.\n"
    "    --no-interior-refs  Perform no instrumentation of references to non-\n"
    "                        zero offsets in code blocks. Implicit when\n"
    "                        --call-trace-client=PROFILER is specified.\n"
    "    --new-workflow      Use the new instrumenter workflow.\n"
    " New workflow options:\n"
    "    --overwrite         Allow output files to be overwritten.\n"
    "\n";

static int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

int InstrumentWithNewWorkflow(const FilePath& input_dll_path,
                              const FilePath& input_pdb_path,
                              const FilePath& output_dll_path,
                              const FilePath& output_pdb_path,
                              const std::string& client_dll_name,
                              bool instrument_interior_references,
                              bool allow_overwrite) {
  LOG(INFO) << "Using new instrumenter workflow.";

  pe::PERelinker relinker;
  relinker.set_input_path(input_dll_path);
  relinker.set_output_path(output_dll_path);
  relinker.set_output_pdb_path(output_pdb_path);
  relinker.set_allow_overwrite(allow_overwrite);

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker.Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return 1;
  }

  // Set up the instrumenting transform and add it to the relinker.
  instrument::transforms::EntryThunkTransform entry_thunk_tx;
  entry_thunk_tx.set_instrument_dll_name(client_dll_name);
  entry_thunk_tx.set_instrument_interior_references(
      instrument_interior_references);
  relinker.AppendTransform(&entry_thunk_tx);

  // We let the PERelinker use the implicit OriginalOrderer.
  if (!relinker.Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return 1;
  }

  return 0;
}

}  // namespace

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

  FilePath input_dll_path(cmd_line->GetSwitchValuePath("input-dll"));
  FilePath input_pdb_path(cmd_line->GetSwitchValuePath("input-pdb"));
  FilePath output_dll_path(cmd_line->GetSwitchValuePath("output-dll"));
  FilePath output_pdb_path(cmd_line->GetSwitchValuePath("output-pdb"));
  std::string client_dll(cmd_line->GetSwitchValueASCII("call-trace-client"));
  bool instrument_interior_references =
      !cmd_line->HasSwitch("no-interior-refs");
  bool new_workflow = cmd_line->HasSwitch("new-workflow");
  bool overwrite = cmd_line->HasSwitch("overwrite");

  if (input_dll_path.empty() || output_dll_path.empty())
    return Usage("You must provide input and output file names.");

  if (client_dll.empty() || LowerCaseEqualsASCII(client_dll, "etw")) {
    client_dll = Instrumenter::kCallTraceClientDllEtw;
  } else if (LowerCaseEqualsASCII(client_dll, "rpc")) {
    client_dll = Instrumenter::kCallTraceClientDllRpc;
  } else if (LowerCaseEqualsASCII(client_dll, "profiler")) {
    client_dll = Instrumenter::kCallTraceClientDllProfiler;
    instrument_interior_references = false;
  }

  if (new_workflow) {
    return InstrumentWithNewWorkflow(input_dll_path,
                                     input_pdb_path,
                                     output_dll_path,
                                     output_pdb_path,
                                     client_dll,
                                     instrument_interior_references,
                                     overwrite);
  }

  // Old workflow.

  if (input_pdb_path.empty()) {
    LOG(INFO) << "--input-pdb not specified, searching for it.";
    if (!pe::FindPdbForModule(input_dll_path, &input_pdb_path) ||
        input_pdb_path.empty()) {
      LOG(ERROR) << "Failed to find PDB for input module.";
      return 1;
    }
  }

  if (output_pdb_path.empty()) {
    output_pdb_path = output_dll_path.ReplaceExtension(L".pdb");
    LOG(INFO) << "Using default value for --output_pdb.";
  }

  LOG(INFO) << "Input image = " << input_dll_path.value();
  LOG(INFO) << "Input PDB = " << input_pdb_path.value();
  LOG(INFO) << "Output image = " << output_dll_path.value();
  LOG(INFO) << "Output PDB = " << output_dll_path.value();
  LOG(INFO) << "Client DLL = " << client_dll;
  LOG(INFO) << "Instrument interior refs = " << instrument_interior_references;

  Instrumenter instrumenter;
  instrumenter.set_client_dll(client_dll.c_str());
  instrumenter.set_instrument_interior_references(
      instrument_interior_references);

  if (!instrumenter.Instrument(input_dll_path,
                               input_pdb_path,
                               output_dll_path,
                               output_pdb_path)) {
    LOG(ERROR)<< "Failed to instrument " << input_dll_path.value().c_str();
    return 1;
  }

  return 0;
}
