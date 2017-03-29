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

#include <set>
#include <unordered_map>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/json/string_escape.h"
#include "base/strings/string16.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/application/application.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/analyzer_factory.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/symbols/dia_symbol_provider.h"
#include "syzygy/refinery/symbols/symbol_provider.h"

namespace {

using AnalyzerName = std::string;
using AnalyzerNames = std::vector<std::string>;
using AnalyzerSet = std::set<AnalyzerName>;
using AnalyzerGraph = std::unordered_map<AnalyzerName, AnalyzerSet>;
using LayerNames = std::vector<std::string>;

class RunAnalyzerApplication : public application::AppImplBase {
 public:
  RunAnalyzerApplication();

  bool ParseCommandLine(const base::CommandLine* command_line);
  int Run();

 private:
  bool AddLayerPrerequisiteAnalyzers(const refinery::AnalyzerFactory& factory);
  bool OrderAnalyzers(const refinery::AnalyzerFactory& factory);

  void PrintFieldAsJson(const char* name, uint64_t value);
  void PrintFieldAsJson(const char* name, uint32_t value);
  void PrintFieldAsJson(const char* name, base::StringPiece value);

  template <typename RecordType>
  void PrintRecordAsJson(scoped_refptr<RecordType> record);
  void PrintRecordAsJson(refinery::TypedBlockRecordPtr typed_block);

  template <typename LayerPtrType>
  void PrintLayerAsJson(const char* layer_name,
                        refinery::ProcessState* process_state);
  void PrintProcessStateAsJson(refinery::ProcessState* process_state);
  void PrintUsage(const base::FilePath& program,
                  const base::StringPiece& message);
  bool AddAnalyzers(const refinery::AnalyzerFactory& factory,
                    refinery::AnalysisRunner* runner);
  bool Analyze(const minidump::Minidump& minidump,
               const refinery::AnalyzerFactory& factory,
               const refinery::Analyzer::ProcessAnalysis& process_analysis);

  std::vector<base::FilePath> mindump_paths_;
  std::string analyzer_names_;
  bool resolve_dependencies_;
  std::string output_layers_;

  DISALLOW_COPY_AND_ASSIGN(RunAnalyzerApplication);
};

// A worker class that knows how to order analyzers topologically by their
// layer dependencies.
class AnalyzerOrderer {
 public:
  explicit AnalyzerOrderer(const refinery::AnalyzerFactory& factory);

  bool CreateGraph(const std::string& names);
  std::string Order();

 private:
  void Visit(const AnalyzerName& name);

  const refinery::AnalyzerFactory& factory_;
  AnalyzerGraph graph_;
  AnalyzerSet visited_;
  AnalyzerSet used_;
  AnalyzerNames ordering_;
};

std::vector<std::string> SplitStringList(const std::string& name_list) {
  return base::SplitString(name_list, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY);
}

std::string JoinAnalyzerSet(const AnalyzerSet& analyzer_set) {
  std::string ret;
  for (const auto& analyzer_name : analyzer_set) {
    if (!ret.empty())
      ret.append(",");

    ret.append(analyzer_name);
  }
  return ret;
}

const char* kLayerNames[] = {
#define LAYER_NAME(layer_name) #layer_name "Layer",
    PROCESS_STATE_LAYERS(LAYER_NAME)
#undef LAYER_NAME
};

bool IsValidLayerName(const std::string& candidate) {
  for (const auto name : kLayerNames) {
    if (candidate == name)
      return true;
  }

  return false;
}

std::string GetValidLayerNames() {
  std::string ret;
  for (const auto name : kLayerNames) {
    if (!ret.empty())
      ret.append(", ");
    ret.append(name);
  }

  return ret;
}

bool IsValidAnalyzerName(const std::string& candidate) {
  refinery::AnalyzerFactory::AnalyzerNames names;
  refinery::StaticAnalyzerFactory factory;
  factory.GetAnalyzerNames(&names);

  for (const auto name : names) {
    if (candidate == name)
      return true;
  }

  return false;
}

std::string GetValidAnalyzerNames() {
  refinery::AnalyzerFactory::AnalyzerNames names;
  refinery::StaticAnalyzerFactory factory;
  factory.GetAnalyzerNames(&names);

  return base::JoinString(names, ", ");
}

const char kUsageFormatStr[] =
    "Usage: %ls [options] <dump files or patterns>\n"
    "\n"
    "  --analyzers=<comma-seperated list of analyzer names>\n"
    "     Configures the set of analyzers to run on each of the dump\n"
    "     files.\n"
    "     Default value: %s\n"
    "  --output-layers=<comma-seperated list of layer names>\n"
    "     The list of layers to output. If no list of analyzer is provided,\n"
    "     this option will configure all analyzers that output the requested\n"
    "     layer or layers.\n"
    "     Default value: %s\n"
    "  --no-dependencies\n"
    "     If provided, the layer dependencies of the requested analyzers\n"
    "     won't be used to supplement the analyzer list.\n";

const char kDefaultAnalyzers[] = "HeapAnalyzer,StackFrameAnalyzer,TebAnalyzer";
const char kDefaultOutputLayers[] = "TypedDataLayer";

bool RunAnalyzerApplication::AddLayerPrerequisiteAnalyzers(
    const refinery::AnalyzerFactory& factory) {
  // Build the transitive closure of all the analyzers we need.
  // The analyzers we've yet to process, initialized to the entire list.
  AnalyzerNames to_process = SplitStringList(analyzer_names_);
  AnalyzerSet selected_analyzers;
  for (const auto& name : to_process)
    selected_analyzers.insert(name);

  while (!to_process.empty()) {
    // Pop one analyzer name off the list to process.
    std::string analyzer_name = to_process.back();
    to_process.pop_back();

    // Get the input layers this analyzer depends on.
    refinery::AnalyzerFactory::Layers input_layers;
    if (!factory.GetInputLayers(analyzer_name, &input_layers))
      return false;

    // Now retrieve all the analyzers that produce these layers, and see about
    // adding them to the mix.
    for (const auto& input_layer : input_layers) {
      refinery::AnalyzerFactory::AnalyzerNames outputting_names;
      factory.GetAnalyzersOutputting(input_layer, &outputting_names);

      for (const auto& outputting_name : outputting_names) {
        bool inserted = selected_analyzers.insert(outputting_name).second;
        if (inserted) {
          // This analyzer was not already in all names, add it to the queue
          // of names to process.
          to_process.push_back(outputting_name);
        }
      }
    }
  }

  analyzer_names_ = JoinAnalyzerSet(selected_analyzers);

  return true;
}

bool RunAnalyzerApplication::OrderAnalyzers(
    const refinery::AnalyzerFactory& factory) {
  // Topologically order the analyzers.
  // Start by building the graph of analyzer dependencies.
  AnalyzerOrderer orderer(factory);

  if (!orderer.CreateGraph(analyzer_names_))
    return false;

  analyzer_names_ = orderer.Order();

  return true;
}

void RunAnalyzerApplication::PrintFieldAsJson(const char* name,
                                              uint64_t value) {
  ::fprintf(out(), "      \"%s\": %llu,\n", name, value);
}

void RunAnalyzerApplication::PrintFieldAsJson(const char* name,
                                              uint32_t value) {
  ::fprintf(out(), "      \"%s\": %u,\n", name, value);
}

void RunAnalyzerApplication::PrintFieldAsJson(const char* name,
                                              base::StringPiece value) {
  std::string escaped_value;
  CHECK(base::EscapeJSONString(value, true, &escaped_value));

  ::fprintf(out(), "      \"%s\": %s,\n", name, escaped_value.c_str());
}

template <typename RecordType>
void RunAnalyzerApplication::PrintRecordAsJson(
    scoped_refptr<RecordType> record) {
  std::string str = record->data().DebugString();

  ::fprintf(out(), "0x%08llX(0x%04X){\n%s}\n", record->range().start(),
            record->range().size(), str.c_str());
}

void RunAnalyzerApplication::PrintRecordAsJson(
    refinery::TypedBlockRecordPtr typed_block) {
  auto data = typed_block->data();

  PrintFieldAsJson("module_id", data.module_id());
  PrintFieldAsJson("type_id", data.type_id());
  PrintFieldAsJson("data_name", data.data_name());
}

template <typename LayerPtrType>
void RunAnalyzerApplication::PrintLayerAsJson(
    const char* layer_name,
    refinery::ProcessState* process_state) {
  DCHECK(process_state);

  LayerPtrType layer;
  if (!process_state->FindLayer(&layer)) {
    LOG(INFO) << "No " << layer_name << " layer";
    return;
  }

  ::fprintf(out(), "  \"%s\": [\n", layer_name);

  for (const auto& record : *layer) {
    ::fprintf(out(), "    {\n");
    PrintFieldAsJson("address", record->range().start());
    PrintFieldAsJson("size", record->range().size());
    PrintRecordAsJson(record);
    ::fprintf(out(), "    },\n");
  }

  ::fprintf(out(), "  ],\n");
}

void RunAnalyzerApplication::PrintProcessStateAsJson(
    refinery::ProcessState* process_state) {
  DCHECK(process_state);

  LayerNames layer_names = SplitStringList(output_layers_);

  ::fprintf(out(), "{\n");

#define PRINT_LAYER(layer_name)                                   \
  if (std::find(layer_names.begin(), layer_names.end(),           \
                #layer_name "Layer") != layer_names.end())        \
    PrintLayerAsJson<refinery::layer_name##LayerPtr>(#layer_name, \
                                                     process_state);

  PROCESS_STATE_LAYERS(PRINT_LAYER)

#undef PRINT_LAYER

  ::fprintf(out(), "}\n");
}

void RunAnalyzerApplication::PrintUsage(const base::FilePath& program,
                                        const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str(),
            kDefaultAnalyzers, kDefaultOutputLayers);
}

RunAnalyzerApplication::RunAnalyzerApplication()
    : AppImplBase("RunAnalyzerApplication"), resolve_dependencies_(true) {
}

bool RunAnalyzerApplication::ParseCommandLine(
    const base::CommandLine* cmd_line) {
  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  if (cmd_line->HasSwitch("no-dependencies"))
    resolve_dependencies_ = false;

  static const char kAnalyzers[] = "analyzers";
  if (cmd_line->HasSwitch(kAnalyzers)) {
    analyzer_names_ = cmd_line->GetSwitchValueASCII(kAnalyzers);

    if (analyzer_names_.empty()) {
      PrintUsage(cmd_line->GetProgram(),
                 "Must provide a non-empty analyzer list with this flag.");
      return false;
    }
    for (const auto& analyzer_name : SplitStringList(analyzer_names_)) {
      if (!IsValidAnalyzerName(analyzer_name)) {
        PrintUsage(cmd_line->GetProgram(),
                   base::StringPrintf(
                       "Analyzer \"%s\" doesn't exist, must be one of \"%s\"",
                       analyzer_name.c_str(), GetValidAnalyzerNames().c_str()));
        return false;
      }
    }
  }

  static const char kOutputLayers[] = "output-layers";
  if (cmd_line->HasSwitch(kOutputLayers)) {
    output_layers_ = cmd_line->GetSwitchValueASCII(kOutputLayers);

    if (output_layers_.empty()) {
      PrintUsage(cmd_line->GetProgram(),
                 "Must provide a non-empty output layer list with this flag.");
      return false;
    }
    for (const auto& layer_name : SplitStringList(output_layers_)) {
      if (!IsValidLayerName(layer_name)) {
        PrintUsage(cmd_line->GetProgram(),
                   base::StringPrintf(
                       "Layer \"%s\" doesn't exist, must be one of \"%s\"",
                       layer_name.c_str(), GetValidLayerNames().c_str()));
        return false;
      }
    }
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
  // If no analyzers are specified, but output layers are, we pick analyzers
  // from the requested layers.
  refinery::StaticAnalyzerFactory analyzer_factory;
  if (!output_layers_.empty() && analyzer_names_.empty()) {
    AnalyzerSet selected_analyzers;
    for (const auto& layer_name : SplitStringList(output_layers_)) {
      refinery::ProcessState::LayerEnum layer =
          refinery::ProcessState::LayerFromName(layer_name);
      if (layer == refinery::ProcessState::UnknownLayer) {
        LOG(ERROR) << "Unknown layer: " << layer_name;
        return 1;
      }

      AnalyzerNames analyzer_names;
      analyzer_factory.GetAnalyzersOutputting(layer, &analyzer_names);
      for (const auto& analyzer_name : analyzer_names)
        selected_analyzers.insert(analyzer_name);
    }

    analyzer_names_ = JoinAnalyzerSet(selected_analyzers);
  }

  if (output_layers_.empty())
    output_layers_ = kDefaultOutputLayers;
  if (analyzer_names_.empty())
    analyzer_names_ = kDefaultAnalyzers;

  if (resolve_dependencies_ &&
      !AddLayerPrerequisiteAnalyzers(analyzer_factory)) {
    LOG(ERROR) << "Unable to add dependent analyzers.";
    return 1;
  }

  if (!OrderAnalyzers(analyzer_factory)) {
    LOG(ERROR) << "Unable to order analyzers.";
    return 1;
  } else {
    LOG(INFO) << "Using analyzer list: " << analyzer_names_;
    LOG(INFO) << "Outputting layers: " << output_layers_;
  }

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
    if (Analyze(minidump, analyzer_factory, analysis)) {
      PrintProcessStateAsJson(&process_state);
    } else {
      LOG(ERROR) << "Failure processing minidump " << minidump_path.value();
    }
  }

  return 0;
}

bool RunAnalyzerApplication::AddAnalyzers(
    const refinery::AnalyzerFactory& factory,
    refinery::AnalysisRunner* runner) {
  AnalyzerNames analyzers = SplitStringList(analyzer_names_);
  for (const auto& analyzer_name : analyzers) {
    std::unique_ptr<refinery::Analyzer> analyzer(
        factory.CreateAnalyzer(analyzer_name));
    if (analyzer) {
      runner->AddAnalyzer(std::move(analyzer));
    } else {
      LOG(ERROR) << "No such analyzer " << analyzer_name;
      return false;
    }
  }

  return true;
}

bool RunAnalyzerApplication::Analyze(
    const minidump::Minidump& minidump,
    const refinery::AnalyzerFactory& factory,
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
  if (!AddAnalyzers(factory, &runner))
    return false;

  return runner.Analyze(minidump, process_analysis) ==
         refinery::Analyzer::ANALYSIS_COMPLETE;
}

AnalyzerOrderer::AnalyzerOrderer(const refinery::AnalyzerFactory& factory)
    : factory_(factory) {
}

bool AnalyzerOrderer::CreateGraph(const std::string& analyzer_names) {
  AnalyzerNames analyzers = SplitStringList(analyzer_names);
  AnalyzerSet all_analyzers;
  for (const AnalyzerName& name : analyzers)
    all_analyzers.insert(name);

  // For each requested analyser, find the layers it inputs. From each of those
  // layers, find the analyzers that output those layers - intersected with
  // the analyzers we care about.
  for (const AnalyzerName& analyzer_name : all_analyzers) {
    refinery::AnalyzerFactory::Layers input_layers;
    if (!factory_.GetInputLayers(analyzer_name, &input_layers))
      return false;

    AnalyzerSet& dependencies = graph_[analyzer_name];
    for (auto input_layer : input_layers) {
      refinery::AnalyzerFactory::AnalyzerNames outputting_names;
      factory_.GetAnalyzersOutputting(input_layer, &outputting_names);
      for (const AnalyzerName& outputting_name : outputting_names) {
        if (all_analyzers.find(outputting_name) != all_analyzers.end()) {
          // Note that the graph may be circular, and it's in particular
          // acceptable for analyzers to consume and produce the same layer.
          // This is the case for e.g. type propagation, which propagates
          // the types of pointers.
          dependencies.insert(outputting_name);
        }
      }
    }
  }

  return true;
}

std::string AnalyzerOrderer::Order() {
  DCHECK(visited_.empty());
  DCHECK(used_.empty());
  DCHECK(ordering_.empty());

  for (const auto& node : graph_)
    Visit(node.first);

  DCHECK(visited_.empty());
  DCHECK_EQ(graph_.size(), used_.size());
  DCHECK_EQ(graph_.size(), ordering_.size());

  return base::JoinString(ordering_, ",");
}

void AnalyzerOrderer::Visit(const AnalyzerName& name) {
  DCHECK(graph_.find(name) != graph_.end());

  if (visited_.find(name) != visited_.end())
    return;

  visited_.insert(name);
  for (const AnalyzerName& dep : graph_[name])
    Visit(dep);

  visited_.erase(name);
  if (used_.find(name) == used_.end()) {
    used_.insert(name);
    ordering_.push_back(name);
  }
}

}  // namespace

int main(int argc, const char* const* argv) {
  base::AtExitManager at_exit_manager;
  base::CommandLine::Init(argc, argv);
  return application::Application<RunAnalyzerApplication>().Run();
}
