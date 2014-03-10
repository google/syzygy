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
#include "syzygy/instrument/instrumenters/asan_instrumenter.h"
#include "syzygy/instrument/instrumenters/bbentry_instrumenter.h"
#include "syzygy/instrument/instrumenters/branch_instrumenter.h"
#include "syzygy/instrument/instrumenters/coverage_instrumenter.h"
#include "syzygy/instrument/instrumenters/entry_call_instrumenter.h"
#include "syzygy/instrument/instrumenters/entry_thunk_instrumenter.h"

namespace instrument {

namespace {

static const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "  Required arguments:\n"
    "    --input-image=<path> The input image to instrument.\n"
    "    --mode=asan|bbentry|branch|calltrace|coverage|profile\n"
    "                            Specifies which instrumentation mode is to\n"
    "                            be used. If this is not specified it is\n"
    "                            equivalent to specifying --mode=calltrace\n"
    "                            (this default behaviour is DEPRECATED).\n"
    "    --output-image=<path>\n"
    "                            The instrumented output image.\n"
    "  DEPRECATED options:\n"
    "    --input-dll is aliased to --input-image.\n"
    "    --output-dll is aliased to --output-image.\n"
    "    --call-trace-client=RPC\n"
    "                            Equivalent to --mode=calltrace.\n"
    "    --call-trace-client=PROFILER\n"
    "                            Equivalent to --mode=profile.\n"
    "    --call-trace-client=<path>\n"
    "                            Equivalent to --mode=calltrace\n"
    "                                 --agent=<path>.\n"
    "  General options (applicable in all modes):\n"
    "    --agent=<path>          If specified indicates exactly which DLL to\n"
    "                            use when instrumenting the provided module.\n"
    "                            If not specified a default agent library\n"
    "                            will be used. This is ignored in ASAN mode.\n"
    "    --debug-friendly        Generate more debugger friendly output by\n"
    "                            making the thunks resolve to the original\n"
    "                            function's name. This is at the cost of the\n"
    "                            uniqueness of address->name resolution.\n"
    "    --inline-fast-path      Inline a fast path into the instrumented\n"
    "                            image.\n"
    "    --input-pdb=<path>      The PDB for the DLL to instrument. If not\n"
    "                            explicitly provided will be searched for.\n"
    "    --filter=<path>         The path of the filter to be used in\n"
    "                            applying the instrumentation. Ranges marked\n"
    "                            in the filter will not be instrumented.\n"
    "    --no-augment-pdb        Indicates that the relinker should not\n"
    "                            augment the output PDB with additional.\n"
    "                            metadata.\n"
    "    --no-strip-strings      Indicates that the relinker should not strip\n"
    "                            the strings when augmenting the PDB. They\n"
    "                            are stripped by default to keep PDB sizes\n"
    "                            down.\n"
    "    --output-pdb=<path>     The PDB for the instrumented DLL. If not\n"
    "                            provided will attempt to generate one.\n"
    "    --overwrite             Allow output files to be overwritten.\n"
    "  asan mode options:\n"
    "    --asan-rtl-options=OPTIONS\n"
    "                            Allows specification of options that will\n"
    "                            influence the ASAN RTL that attaches to the\n"
    "                            instrumented module. For descriptions of\n"
    "                            these options see common/asan_parameters. If\n"
    "                            not specified then the defaults of the RTL\n"
    "                            will be used.\n"
    "    --instrumentation-rate=DOUBLE\n"
    "                            Specifies the fraction of instructions to\n"
    "                            be instrumented, as a value in the range\n"
    "                            0..1, inclusive. Defaults to 1.\n"
    "    --no-interceptors\n     Disable the interception of the functions\n"
    "                            like memset, memcpy, stcpy, ReadFile... to\n"
    "                            check their parameters.\n"
    "    --no-liveness-analysis  Disables register and flags liveness\n"
    "                            analysis.\n"
    "    --no-redundancy-analysis\n"
    "                            Disables redundant memory access analysis.\n"
    "  branch mode options:\n"
    "    --buffering             Enable per-thread buffering of events.\n"
    "    --fs-slot=<slot>        Specify which FS slot to use for thread\n"
    "                            local storage.\n"
    "  calltrace mode options:\n"
    "    --instrument-imports    Also instrument calls to imports.\n"
    "    --module-entry-only     If specified then the per-function entry\n"
    "                            hook will not be used and only module entry\n"
    "                            points will be hooked.\n"
    "    --no-unsafe-refs        Perform no instrumentation of references\n"
    "                            between code blocks that contain anything\n"
    "                            but C/C++.\n"
    "  profile mode options:\n"
    "    --instrument-imports    Also instrument calls to imports.\n"
    "\n";

}  // namespace

void InstrumentApp::ParseDeprecatedMode(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  std::string client = cmd_line->GetSwitchValueASCII("call-trace-client");

  if (client.empty()) {
    LOG(INFO) << "DEPRECATED: No mode specified, using --mode=calltrace.";
    instrumenter_.reset(new instrumenters::EntryThunkInstrumenter(
        instrumenters::EntryThunkInstrumenter::CALL_TRACE));
    return;
  }

  if (LowerCaseEqualsASCII(client, "profiler")) {
    LOG(INFO) << "DEPRECATED: Using --mode=profile.";
    instrumenter_.reset(new instrumenters::EntryThunkInstrumenter(
        instrumenters::EntryThunkInstrumenter::PROFILE));
  } else if (LowerCaseEqualsASCII(client, "rpc")) {
    LOG(INFO) << "DEPRECATED: Using --mode=calltrace.";
    instrumenter_.reset(new instrumenters::EntryThunkInstrumenter(
        instrumenters::EntryThunkInstrumenter::CALL_TRACE));
  } else {
    LOG(INFO) << "DEPRECATED: Using --mode=calltrace --agent=" << client << ".";
    instrumenter_.reset(new instrumenters::EntryThunkInstrumenter(
        instrumenters::EntryThunkInstrumenter::CALL_TRACE));
  }
}

bool InstrumentApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help"))
    return Usage(cmd_line, "");

  // Get the mode and the default client DLL.
  if (!cmd_line->HasSwitch("mode")) {
    // TODO(chrisha): Remove this once build scripts and profiling tools have
    //     been updated.
    ParseDeprecatedMode(cmd_line);
  } else {
    std::string mode = cmd_line->GetSwitchValueASCII("mode");
    if (LowerCaseEqualsASCII(mode, "asan")) {
      instrumenter_.reset(new instrumenters::AsanInstrumenter());
    } else if (LowerCaseEqualsASCII(mode, "bbentry")) {
      instrumenter_.reset(new instrumenters::BasicBlockEntryInstrumenter());
    } else if (LowerCaseEqualsASCII(mode, "branch")) {
      instrumenter_.reset(new instrumenters::BranchInstrumenter());
    } else if (LowerCaseEqualsASCII(mode, "calltrace")) {
      instrumenter_.reset(new instrumenters::EntryThunkInstrumenter(
          instrumenters::EntryThunkInstrumenter::CALL_TRACE));
    } else if (LowerCaseEqualsASCII(mode, "coverage")) {
      instrumenter_.reset(new instrumenters::CoverageInstrumenter());
    } else if (LowerCaseEqualsASCII(mode, "profile")) {
      instrumenter_.reset(new instrumenters::EntryCallInstrumenter());
    } else {
      return Usage(cmd_line,
                   base::StringPrintf("Unknown instrumentation mode: %s.",
                                      mode.c_str()).c_str());
    }
  }
  DCHECK(instrumenter_.get() != NULL);

  return instrumenter_->ParseCommandLine(cmd_line);
}

int InstrumentApp::Run() {
  DCHECK(instrumenter_.get() != NULL);

  return instrumenter_->Instrument() ? 0 : 1;
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
