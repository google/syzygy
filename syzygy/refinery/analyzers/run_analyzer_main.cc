// Copyright 2016 Google Inc. All Rights Reserved.
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

// Runs a particular analyzer over a minidump or set of minidumps.
#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/strings/string16.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "syzygy/application/application.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/heap_analyzer.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/analyzers/stack_analyzer.h"
#include "syzygy/refinery/analyzers/stack_frame_analyzer.h"
#include "syzygy/refinery/analyzers/teb_analyzer.h"
#include "syzygy/refinery/analyzers/thread_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
#include "syzygy/refinery/symbols/symbol_provider.h"

namespace {

class RunAnalyzerApplication : public application::AppImplBase {
 public:
  RunAnalyzerApplication();

  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();

 private:
  template <typename LayerPtrType>
  void PrintLayer(const char* layer_name,
                  refinery::ProcessState* process_state);
  void PrintProcessState(refinery::ProcessState* process_state);
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
  bool AddAnalyzers(refinery::AnalysisRunner* runner);
  bool Analyze(const minidump::Minidump& minidump,
               const refinery::Analyzer::ProcessAnalysis& process_analysis);

  std::vector<base::FilePath> mindump_paths_;
  std::vector<std::string> analyzer_names_;

  DISALLOW_COPY_AND_ASSIGN(RunAnalyzerApplication);
};

const char kUsageFormatStr[] =
    "Usage: %ls [options] <dump files or patterns>\n"
    "\n"
    "  --analyzers=<comma-seperated list of analyzer names>\n"
    "     Configures the set of analyzers to run on each of the dump\n"
    "     files.\n";

const char kDefaultAnalyzers[] = "MemoryAnalyzer,ModuleAnalyzer,HeapAnalyzer";

template <typename LayerPtrType>
void RunAnalyzerApplication::PrintLayer(const char* layer_name,
                                        refinery::ProcessState* process_state) {
  DCHECK(process_state);

  LayerPtrType layer;
  if (!process_state->FindLayer(&layer)) {
    LOG(INFO) << "No " << layer_name << " layer";
    return;
  }

  for (const auto& record : *layer) {
    std::string str = record->data().DebugString();

    ::fprintf(out(), "0x%08llX(0x%04X){\n%s}\n", record->range().start(),
              record->range().size(), str.c_str());
  }
}

void RunAnalyzerApplication::PrintProcessState(
    refinery::ProcessState* process_state) {
  DCHECK(process_state);

#define PRINT_LAYER(layer_name) \
  PrintLayer<refinery::layer_name##LayerPtr>(#layer_name, process_state);

  PROCESS_STATE_LAYERS(PRINT_LAYER)

#undef PRINT_LAYER
}

void RunAnalyzerApplication::PrintUsage(const base::FilePath& program,
                                        const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

RunAnalyzerApplication::RunAnalyzerApplication()
    : AppImplBase("RunAnalyzerApplication") {
}

bool RunAnalyzerApplication::ParseCommandLine(
    const base::CommandLine* cmd_line) {
  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  std::string analyzers = cmd_line->GetSwitchValueASCII("analyzers");
  if (analyzers.empty())
    analyzers = kDefaultAnalyzers;

  analyzer_names_ = base::SplitString(analyzers, ",", base::TRIM_WHITESPACE,
                                      base::SPLIT_WANT_NONEMPTY);
  if (analyzer_names_.empty()) {
    PrintUsage(cmd_line->GetProgram(),
               "Must provide a non-empty analyzer list.");
    return false;
  }

  for (const auto& arg : cmd_line->GetArgs()) {
    if (!AppendMatchingPaths(base::FilePath(arg), &mindump_paths_)) {
      PrintUsage(
          cmd_line->GetProgram(),
          base::StringPrintf("Can't find file or pattern \"%s\"", arg.c_str()));
      return false;
    }
  }

  if (mindump_paths_.empty()) {
    PrintUsage(cmd_line->GetProgram(),
               "You must provide at least one dump file.");
    return false;
  }

  return true;
}

int RunAnalyzerApplication::Run() {
  scoped_refptr<refinery::SymbolProvider> symbol_provider(
      new refinery::SymbolProvider());
  scoped_refptr<refinery::DiaSymbolProvider> dia_symbol_provider(
      new refinery::DiaSymbolProvider());

  for (const auto& minidump_path : mindump_paths_) {
    ::fprintf(out(), "Processing \"%ls\"\n", minidump_path.value().c_str());

    minidump::FileMinidump minidump;
    if (!minidump.Open(minidump_path)) {
      LOG(ERROR) << "Unable to open dump file.";
      return 1;
    }

    refinery::ProcessState process_state;
    refinery::SimpleProcessAnalysis analysis(
        &process_state, dia_symbol_provider, symbol_provider);
    if (Analyze(minidump, analysis)) {
      PrintProcessState(&process_state);
    } else {
      LOG(ERROR) << "Failure processing minidump " << minidump_path.value();
    }
  }

  return 0;
}

bool RunAnalyzerApplication::AddAnalyzers(refinery::AnalysisRunner* runner) {
  scoped_ptr<refinery::Analyzer> analyzer;
  // TODO(siggi): Figure a better way to do this.
  for (const auto& analyzer_name : analyzer_names_) {
    if (analyzer_name == "MemoryAnalyzer") {
      analyzer.reset(new refinery::MemoryAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "ModuleAnalyzer") {
      analyzer.reset(new refinery::ModuleAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "HeapAnalyzer") {
      analyzer.reset(new refinery::HeapAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "StackAnalyzer") {
      analyzer.reset(new refinery::StackAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "StackFrameAnalyzer") {
      analyzer.reset(new refinery::StackFrameAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "TebAnalyzer") {
      analyzer.reset(new refinery::TebAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else if (analyzer_name == "ThreadAnalyzer") {
      analyzer.reset(new refinery::ThreadAnalyzer());
      runner->AddAnalyzer(analyzer.Pass());
    } else {
      LOG(ERROR) << "No such analyzer " << analyzer_name;
      return false;
    }
  }

  return true;
}

bool RunAnalyzerApplication::Analyze(
    const minidump::Minidump& minidump,
    const refinery::Analyzer::ProcessAnalysis& process_analysis) {
  DCHECK(process_analysis.process_state());

  minidump::Minidump::Stream sys_info_stream =
      minidump.FindNextStream(nullptr, SystemInfoStream);

  MINIDUMP_SYSTEM_INFO system_info = {};
  if (!sys_info_stream.ReadAndAdvanceElement(&system_info)) {
    LOG(ERROR) << "Unable to read system info stream.";
    return false;
  }

  VLOG(1) << base::StringPrintf("Systeminformation");
  VLOG(1) << base::StringPrintf("  ProcessorArchitecture 0x%04X",
                                system_info.ProcessorArchitecture);
  VLOG(1) << base::StringPrintf("  ProcessorLevel 0x%04X",
                                system_info.ProcessorLevel);
  VLOG(1) << base::StringPrintf("  ProcessorRevision 0x%04X",
                                system_info.ProcessorRevision);
  VLOG(1) << base::StringPrintf("  NumberOfProcessors %d",
                                system_info.NumberOfProcessors);
  VLOG(1) << base::StringPrintf("  ProductType %d", system_info.ProductType);
  VLOG(1) << base::StringPrintf("  MajorVersion 0x%08X",
                                system_info.MajorVersion);
  VLOG(1) << base::StringPrintf("  MinorVersion 0x%08X",
                                system_info.MinorVersion);
  VLOG(1) << base::StringPrintf("  BuildNumber 0x%08X",
                                system_info.BuildNumber);
  VLOG(1) << base::StringPrintf("  PlatformId 0x%08X", system_info.PlatformId);
  VLOG(1) << base::StringPrintf("  CSDVersionRva 0x%08X",
                                system_info.CSDVersionRva);
  VLOG(1) << base::StringPrintf("  SuiteMask 0x%04X", system_info.SuiteMask);

  VLOG(1) << "  CPU information:";
  VLOG(1) << base::StringPrintf("    VendorId 0x%08X:0x%08X:0x%08X",
                                system_info.Cpu.X86CpuInfo.VendorId[0],
                                system_info.Cpu.X86CpuInfo.VendorId[1],
                                system_info.Cpu.X86CpuInfo.VendorId[1]);

  VLOG(1) << base::StringPrintf("    VersionInformation 0x%08X",
                                system_info.Cpu.X86CpuInfo.VersionInformation);
  VLOG(1) << base::StringPrintf("    FeatureInformation 0x%08X",
                                system_info.Cpu.X86CpuInfo.FeatureInformation);
  VLOG(1) << base::StringPrintf(
      "    AMDExtendedCpuFeatures 0x%08X",
      system_info.Cpu.X86CpuInfo.AMDExtendedCpuFeatures);

  refinery::AnalysisRunner runner;
  if (!AddAnalyzers(&runner))
    return false;

  return runner.Analyze(minidump, process_analysis) ==
         refinery::Analyzer::ANALYSIS_COMPLETE;
}

}  // namespace

int main(int argc, const char* const* argv) {
  base::AtExitManager at_exit_manager;
  base::CommandLine::Init(argc, argv);
  return application::Application<RunAnalyzerApplication>().Run();
}
