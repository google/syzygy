// Copyright 2015 Google Inc. All Rights Reserved.
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

// Runs the refinery over a minidump and outputs the validation report.

#include <iostream>
#include <memory>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/strings/stringprintf.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/exception_analyzer.h"
#include "syzygy/refinery/analyzers/heap_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/stack_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
#include "syzygy/refinery/symbols/symbol_provider.h"
#include "syzygy/refinery/validators/exception_handler_validator.h"

namespace {

using minidump::Minidump;
using refinery::AnalysisRunner;
using refinery::Analyzer;
using refinery::ProcessState;
using refinery::ValidationReport;
using refinery::Validator;

const char kUsage[] =
  "Usage: %ls --dump=<dump file>\n"
  "\n"
  "  Runs the refinery analysis and validation, then prints the validation \n"
  "  report.\n";

bool ParseCommandLine(const base::CommandLine* cmd,
                      base::FilePath* dump_path) {
  *dump_path = cmd->GetSwitchValuePath("dump");
  if (dump_path->empty()) {
    LOG(ERROR) << "Missing dump file.";
    LOG(ERROR) << base::StringPrintf(kUsage, cmd->GetProgram().value().c_str());
    return false;
  }

  return true;
}

bool Analyze(const Minidump& minidump, ProcessState* process_state) {
  AnalysisRunner runner;

  std::unique_ptr<Analyzer> analyzer(new refinery::MemoryAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));
  analyzer.reset(new refinery::ThreadAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));
  analyzer.reset(new refinery::ExceptionAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));
  analyzer.reset(new refinery::ModuleAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));
  analyzer.reset(new refinery::HeapAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));
  analyzer.reset(new refinery::StackAnalyzer());
  runner.AddAnalyzer(std::move(analyzer));

  scoped_refptr<refinery::SymbolProvider> symbol_provider(
      new refinery::SymbolProvider());
  scoped_refptr<refinery::DiaSymbolProvider> dia_symbol_provider(
      new refinery::DiaSymbolProvider());

  refinery::SimpleProcessAnalysis analysis(process_state, dia_symbol_provider,
                                           symbol_provider);

  return runner.Analyze(minidump, analysis) == Analyzer::ANALYSIS_COMPLETE;
}

bool Validate(ProcessState* process_state, ValidationReport* report) {
  refinery::ExceptionHandlerValidator validator;
  if (validator.Validate(process_state, report) !=
      Validator::VALIDATION_COMPLETE) {
    LOG(ERROR) << "Exception handler chain validation failed";
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, const char* const* argv) {
  base::CommandLine::Init(argc, argv);

  // Get the dump.
  base::FilePath dump_path;
  if (!ParseCommandLine(base::CommandLine::ForCurrentProcess(), &dump_path))
    return 1;

  minidump::FileMinidump minidump;
  if (!minidump.Open(dump_path)) {
    LOG(ERROR) << "Unable to open dump file.";
    return 1;
  }

  // Analyze.
  ProcessState process_state;
  if (!Analyze(minidump, &process_state))
    return 1;

  // Validate and output.
  ValidationReport report;
  if (!Validate(&process_state, &report))
    return 1;

  std::cout << "Validation report:";
  std::cout << report.DebugString();

  return 0;
}
