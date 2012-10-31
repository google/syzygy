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
// Defines the InstrumentApp class, which implements the command-line
// "instrument" tool.

#include "syzygy/instrument/instrument_app.h"

#include <algorithm>
#include <iostream>

#include "base/string_util.h"
#include "base/stringprintf.h"
#include "syzygy/instrument/mutators/add_bb_ranges_stream.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"
#include "syzygy/instrument/transforms/coverage_transform.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/instrument/transforms/thunk_import_references_transform.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {

namespace {

using block_graph::BlockGraph;
using pe::Decomposer;
using pe::PEFile;

static const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "  Required arguments:\n"
    "    --input-image=<path> The input image to instrument.\n"
    "    --mode=asan|bbentry|calltrace|coverage|profile\n"
    "                         Specifies which instrumentation mode is to be\n"
    "                         used. If this is not specified it is equivalent\n"
    "                         to specifying --mode=calltrace (this default\n"
    "                         behaviour is DEPRECATED).\n"
    "    --output-image=<path>\n"
    "                         The instrumented output image.\n"
    "  DEPRECATED options:\n"
    "    --input-dll is aliased to --input-image.\n"
    "    --output-dll is aliased to --output-image.\n"
    "    --call-trace-client=RPC\n"
    "                         Equivalent to --mode=calltrace.\n"
    "    --call-trace-client=PROFILER\n"
    "                         Equivalent to --mode=profile.\n"
    "    --call-trace-client=<path>\n"
    "                         Equivalent to --mode=calltrace --agent=<path>.\n"
    "  General options (applicable in all modes):\n"
    "    --agent=<path>       If specified indicates exactly which DLL should\n"
    "                         be used in instrumenting the provided module.\n"
    "                         If not specified a default agent library will\n"
    "                         be used. This is ignored in ASAN mode.\n"
    "    --debug-friendly     Generate more debugger friendly output by\n"
    "                         making the thunks resolve to the original\n"
    "                         function's name. This is at the cost of the\n"
    "                         uniqueness of address->name resolution.\n"
    "    --input-pdb=<path>   The PDB for the DLL to instrument. If not\n"
    "                         explicitly provided will be searched for.\n"
    "    --no-augment-pdb     Indicates that the relinker should not augment\n"
    "                         the output PDB with additional metadata.\n"
    "    --no-strip-strings   Indicates that the relinker should not strip\n"
    "                         the strings when augmenting the PDB. They are\n"
    "                         stripped by default to keep PDB sizes down.\n"
    "    --output-pdb=<path>  The PDB for the instrumented DLL. If not\n"
    "                         provided will attempt to generate one.\n"
    "    --overwrite          Allow output files to be overwritten.\n"
    "  calltrace mode options:\n"
    "    --instrument-imports Also instrument calls to imports.\n"
    "    --module-entry-only  If specified then the per-function entry hook\n"
    "                         will not be used and only module entry points\n"
    "                         will be hooked.\n"
    "    --no-unsafe-refs     Perform no instrumentation of references\n"
    "                         between code blocks that contain anything but\n"
    "                         C/C++.\n"
    "  profile mode options:\n"
    "    --instrument-imports Also instrument calls to imports.\n"
    "\n";

}  // namespace

const char InstrumentApp::kCallTraceClientDllBasicBlockEntry[] =
    "basic_block_entry_client.dll";
const char InstrumentApp::kCallTraceClientDllCoverage[] = "coverage_client.dll";
const char InstrumentApp::kCallTraceClientDllProfile[] = "profile_client.dll";
const char InstrumentApp::kCallTraceClientDllRpc[] = "call_trace_client.dll";

pe::PERelinker& InstrumentApp::GetRelinker() {
  if (relinker_.get() == NULL) {
    relinker_.reset(new pe::PERelinker());
    CHECK(relinker_.get() != NULL);
  }
  return *(relinker_.get());
}

void InstrumentApp::ParseDeprecatedMode(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  std::string client = cmd_line->GetSwitchValueASCII("call-trace-client");

  if (client.empty()) {
    LOG(INFO) << "DEPRECATED: No mode specified, using --mode=calltrace.";
    mode_ = kInstrumentCallTraceMode;
    client_dll_ = kCallTraceClientDllRpc;
    return;
  }

  if (LowerCaseEqualsASCII(client, "profiler")) {
    LOG(INFO) << "DEPRECATED: Using --mode=profile.";
    mode_ = kInstrumentProfileMode;
    client_dll_ = kCallTraceClientDllProfile;
  } else if (LowerCaseEqualsASCII(client, "rpc")) {
    LOG(INFO) << "DEPRECATED: Using --mode=calltrace.";
    mode_ = kInstrumentCallTraceMode;
    client_dll_ = kCallTraceClientDllRpc;
  } else {
    LOG(INFO) << "DEPRECATED: Using --mode=calltrace --agent=" << client << ".";
    mode_ = kInstrumentCallTraceMode;
    client_dll_ = client;
  }
}

bool InstrumentApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help"))
    return Usage(cmd_line, "");

  // TODO(chrisha): Simplify the input/output image parsing once external
  //     tools have been updated.

  // Parse the input image.
  if (cmd_line->HasSwitch("input-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --input-dll.";
    input_dll_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-dll"));
  } else {
    input_dll_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-image"));
  }

  // Parse the output image.
  if (cmd_line->HasSwitch("output-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --output-dll.";
    output_dll_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("output-dll"));
  } else {
    output_dll_path_ = AbsolutePath(cmd_line->GetSwitchValuePath(
        "output-image"));
  }

  // Ensure that both input and output have been specified.
  if (input_dll_path_.empty() || output_dll_path_.empty())
    return Usage(cmd_line, "You must provide input and output file names.");

  // Get the mode and the default client DLL.
  if (!cmd_line->HasSwitch("mode")) {
    // TODO(chrisha): Remove this once build scripts and profiling tools have
    //     been updated.
    ParseDeprecatedMode(cmd_line);
  } else {
    std::string mode = cmd_line->GetSwitchValueASCII("mode");
    if (LowerCaseEqualsASCII(mode, "asan")) {
      mode_ = kInstrumentAsanMode;
    } else if (LowerCaseEqualsASCII(mode, "bbentry")) {
      mode_ = kInstrumentBasicBlockEntryMode;
      client_dll_ = kCallTraceClientDllBasicBlockEntry;
    } else if (LowerCaseEqualsASCII(mode, "calltrace")) {
      mode_ = kInstrumentCallTraceMode;
      client_dll_ = kCallTraceClientDllRpc;
    } else if (LowerCaseEqualsASCII(mode, "coverage")) {
      mode_ = kInstrumentCoverageMode;
      client_dll_ = kCallTraceClientDllCoverage;
    } else if (LowerCaseEqualsASCII(mode, "profile")) {
      mode_ = kInstrumentProfileMode;
      client_dll_ = kCallTraceClientDllProfile;
    } else {
      return Usage(cmd_line,
                   base::StringPrintf("Unknown instrumentation mode: %s.",
                                      mode.c_str()).c_str());
    }

    LOG(INFO) << "Default agent for mode " << mode << " is \""
              << client_dll_ << "\".";
  }
  DCHECK_NE(kInstrumentInvalidMode, mode_);

  // Parse the custom agent if one is specified.
  if (cmd_line->HasSwitch("agent")) {
    if (mode_ == kInstrumentAsanMode) {
      // TODO(siggi): Make this work properly!
      LOG(WARNING) << "Ignoring --agent in asan mode.";
    } else {
      client_dll_ = cmd_line->GetSwitchValueASCII("agent");
      LOG(INFO) << "Got custom agent \"" << client_dll_ << "\".";
    }
  }

  // Parse the remaining command line arguments. Not all of these are valid in
  // all modes, but we don't care too much about ignored arguments.
  input_pdb_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("output-pdb"));
  allow_overwrite_ = cmd_line->HasSwitch("overwrite");
  no_augment_pdb_ = cmd_line->HasSwitch("no-augment-pdb");
  no_strip_strings_ = cmd_line->HasSwitch("no-strip-strings");
  debug_friendly_ = cmd_line->HasSwitch("debug-friendly");
  thunk_imports_ = cmd_line->HasSwitch("instrument-imports");
  instrument_unsafe_references_ = !cmd_line->HasSwitch("no-unsafe-refs");
  module_entry_only_ = cmd_line->HasSwitch("module-entry-only");

  // Set per-mode overrides as necessary.
  switch (mode_) {
    case kInstrumentBasicBlockEntryMode:
    case kInstrumentCoverageMode: {
      thunk_imports_ = false;
      instrument_unsafe_references_ = false;
      module_entry_only_ = true;
    } break;

    case kInstrumentProfileMode: {
      instrument_unsafe_references_ = false;
      module_entry_only_ = false;
    } break;

    default: break;
  }

  return true;
}

int InstrumentApp::Run() {
  DCHECK_NE(kInstrumentInvalidMode, mode_);

  pe::PERelinker& relinker = GetRelinker();
  relinker.set_input_path(input_dll_path_);
  relinker.set_input_pdb_path(input_pdb_path_);
  relinker.set_output_path(output_dll_path_);
  relinker.set_output_pdb_path(output_pdb_path_);
  relinker.set_allow_overwrite(allow_overwrite_);
  relinker.set_augment_pdb(!no_augment_pdb_);
  relinker.set_strip_strings(!no_strip_strings_);

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker.Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return 1;
  }

  // A list of all possible transforms that we will need.
  scoped_ptr<instrument::transforms::AsanTransform> asan_transform;
  scoped_ptr<instrument::transforms::BasicBlockEntryHookTransform>
      basic_block_entry_transform;
  scoped_ptr<instrument::transforms::EntryThunkTransform> entry_thunk_tx;
  scoped_ptr<instrument::transforms::ThunkImportReferencesTransform>
      import_thunk_tx;
  scoped_ptr<instrument::transforms::CoverageInstrumentationTransform>
      coverage_tx;
  scoped_ptr<instrument::mutators::AddBasicBlockRangesStreamPdbMutator>
      add_bb_addr_stream_mutator;

  // We are instrumenting in ASAN mode.
  if (mode_ == kInstrumentAsanMode) {
    asan_transform.reset(new instrument::transforms::AsanTransform);
    relinker.AppendTransform(asan_transform.get());
  } else if (mode_ == kInstrumentBasicBlockEntryMode) {
    // If we're in basic-block-entry mode, we need to apply the basic block
    // entry hook transform (which adds basic-block frequency structures to
    // the image and thunks the entry points) and we need to augment the PDB
    // file with the basic block addresses.
    basic_block_entry_transform.reset(
        new instrument::transforms::BasicBlockEntryHookTransform);
    basic_block_entry_transform->set_instrument_dll_name(client_dll_);
    basic_block_entry_transform->set_src_ranges_for_thunks(debug_friendly_);
    relinker.AppendTransform(basic_block_entry_transform.get());

    add_bb_addr_stream_mutator.reset(
        new instrument::mutators::AddBasicBlockRangesStreamPdbMutator(
            basic_block_entry_transform->bb_ranges()));
    relinker.AppendPdbMutator(add_bb_addr_stream_mutator.get());
  } else if (mode_ == kInstrumentCoverageMode) {
    // If we're in coverage mode, we need to add coverage structures to
    // the image and we need to augment the PDB file with the basic block
    // addresses.
    coverage_tx.reset(
        new instrument::transforms::CoverageInstrumentationTransform);
    coverage_tx->set_instrument_dll_name(client_dll_);
    coverage_tx->set_src_ranges_for_thunks(debug_friendly_);
    relinker.AppendTransform(coverage_tx.get());

    add_bb_addr_stream_mutator.reset(
        new instrument::mutators::AddBasicBlockRangesStreamPdbMutator(
            coverage_tx->bb_ranges()));
    relinker.AppendPdbMutator(add_bb_addr_stream_mutator.get());
  } else {
    // We're either in calltrace mode or profile mode. Each of these
    // use the entry_thunk_tx, so we handle them in the same manner.
    DCHECK(mode_ == kInstrumentCallTraceMode ||
           mode_ == kInstrumentProfileMode);

    // Set up the entry thunk instrumenting transform and add it to the
    // relinker.
    entry_thunk_tx.reset(new instrument::transforms::EntryThunkTransform);
    entry_thunk_tx->set_instrument_dll_name(client_dll_);
    entry_thunk_tx->set_instrument_unsafe_references(
        instrument_unsafe_references_);
    entry_thunk_tx->set_src_ranges_for_thunks(debug_friendly_);
    entry_thunk_tx->set_only_instrument_module_entry(module_entry_only_);
    relinker.AppendTransform(entry_thunk_tx.get());

    // If we are thunking imports then add the appropriate transform.
    if (thunk_imports_) {
      import_thunk_tx.reset(
          new instrument::transforms::ThunkImportReferencesTransform);
      import_thunk_tx->ExcludeModule(client_dll_);
      relinker.AppendTransform(import_thunk_tx.get());
    }
  }

  // We let the PERelinker use the implicit OriginalOrderer.
  if (!relinker.Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return 1;
  }

  return 0;
}

bool InstrumentApp::Usage(const CommandLine* cmd_line,
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

}  // namespace instrument
