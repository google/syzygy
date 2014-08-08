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
// Parses a module and ETW trace files, generating an ordering of the
// blocks in the decomposed image.

#include "syzygy/reorder/reorder_app.h"

#include <objbase.h>

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/indexed_frequency_data_serializer.h"
#include "syzygy/pe/find.h"
#include "syzygy/reorder/basic_block_optimizer.h"
#include "syzygy/reorder/dead_code_finder.h"
#include "syzygy/reorder/linear_order_generator.h"
#include "syzygy/reorder/random_order_generator.h"

namespace reorder {

namespace {

using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::IndexedFrequencyInformation;
using grinder::basic_block_util::ModuleIndexedFrequencyMap;
using grinder::basic_block_util::LoadBasicBlockRanges;
using grinder::basic_block_util::FindIndexedFrequencyInfo;
using grinder::basic_block_util::RelativeAddressRangeVector;
using grinder::IndexedFrequencyDataSerializer;

static const char kUsageFormatStr[] =
    "Usage: %ls [options] [log files ...]\n"
    "  Required Options:\n"
    "    --instrumented-image=<path> the path to the instrumented image file.\n"
    "    --output-file=<path> the output file.\n"
    "  Optional Options:\n"
    "    --input-image=<path> the input image file to reorder. If this is not\n"
    "        specified it will be inferred from the instrumented image's\n"
    "        metadata.\n"
    "    --basic-block-entry-counts=PATH the path to the JSON file containing\n"
    "        the summary basic-block entry counts for the image. If this is\n"
    "        given then the input image is also required.\n"
    "    --seed=INT generates a random ordering; don't specify ETW log files.\n"
    "    --list-dead-code instead of an ordering, output the set of functions\n"
    "        not visited during the trace.\n"
    "    --pretty-print enables pretty printing of the JSON output file.\n"
    "    --reorderer-flags=<comma separated reorderer flags>\n"
    "  Reorderer Flags:\n"
    "    no-code: Do not reorder code sections.\n"
    "    no-data: Do not reorder data sections.\n"
    "  Deprecated Options:\n"
    "    --instrumented-dll=<path> aliases to --instrumented-image.\n"
    "    --input-dll=<path> aliases to --input-image.\n";

// Parses reorderer flags. Returns true on success, false otherwise. On
// failure, also outputs Usage with an error message.
bool ParseFlags(const std::string& flags_str, Reorderer::Flags* flags) {
  DCHECK(flags != NULL);

  // Set the default flags value.
  Reorderer::Flags out_flags =
      Reorderer::kFlagReorderData | Reorderer::kFlagReorderCode;

  // If there is a string to process then extract its flags.
  if (!flags_str.empty()) {
    typedef std::vector<std::string> StringVector;
    StringVector text_flags;
    base::SplitString(flags_str, ',', &text_flags);
    StringVector::const_iterator flag_iter = text_flags.begin();
    for (; flag_iter != text_flags.end(); ++flag_iter) {
      if (*flag_iter == "no-data") {
        out_flags &= ~Reorderer::kFlagReorderData;
      } else if (*flag_iter == "no-code") {
        out_flags &= ~Reorderer::kFlagReorderCode;
      } else if (!flag_iter->empty()) {
        LOG(ERROR) << "Unknown reorderer flag: " << *flag_iter << ".";
        return false;
      }
    }
  }

  // Set the return value.
  *flags = out_flags;

  return true;
}

}  // namespace

const char ReorderApp::kInstrumentedImage[] = "instrumented-image";
const char ReorderApp::kOutputFile[] = "output-file";
const char ReorderApp::kInputImage[] = "input-image";
const char ReorderApp::kBasicBlockEntryCounts[] = "basic-block-entry-counts";
const char ReorderApp::kSeed[] = "seed";
const char ReorderApp::kListDeadCode[] = "list-dead-code";
const char ReorderApp::kPrettyPrint[] = "pretty-print";
const char ReorderApp::kReordererFlags[] = "reorderer-flags";
const char ReorderApp::kInstrumentedDll[] = "instrumented-dll";
const char ReorderApp::kInputDll[] = "input-dll";

ReorderApp::ReorderApp()
    : AppImplBase("Reorder"),
      mode_(kInvalidMode),
      seed_(0),
      pretty_print_(false),
      flags_(0) {
}

bool ReorderApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);
  DCHECK_EQ(kInvalidMode, mode_);

  // Parse the instrumented image path.
  if (!GetDeprecatedSwitch(command_line,
                           kInstrumentedImage,
                           kInstrumentedDll,
                           &CommandLine::GetSwitchValuePath,
                           &instrumented_image_path_) ||
      instrumented_image_path_.empty()) {
    return Usage(command_line, "Invalid or missing instrumented image path.");
  }

  // Parse the output file path.
  output_file_path_ = command_line->GetSwitchValuePath(kOutputFile);
  if (output_file_path_.empty()) {
    return Usage(command_line, "Invalid or missing output file path.");
  }

  // Parse the (optional) input image path.
  if (!GetDeprecatedSwitch(command_line,
                           kInputImage,
                           kInputDll,
                           &CommandLine::GetSwitchValuePath,
                           &input_image_path_)) {
    return Usage(command_line, "Invalid input image path.");
  }

  bb_entry_count_file_path_ =
      command_line->GetSwitchValuePath(kBasicBlockEntryCounts);

  // Parse the reorderer flags.
  std::string flags_str(command_line->GetSwitchValueASCII(kReordererFlags));
  if (!ParseFlags(flags_str, &flags_)) {
    return Usage(command_line, "Invalid reorderer flags");
  }

  // Parse the pretty-print switch.
  pretty_print_ = command_line->HasSwitch(kPrettyPrint);

  // Make all of the input paths absolute.
  input_image_path_ = AbsolutePath(input_image_path_);
  instrumented_image_path_ = AbsolutePath(instrumented_image_path_);
  output_file_path_ = AbsolutePath(output_file_path_);
  bb_entry_count_file_path_ = AbsolutePath(bb_entry_count_file_path_);

  // Capture the (possibly empty) set of trace files to read.
  for (size_t i = 0; i < command_line->GetArgs().size(); ++i) {
    const base::FilePath pattern(command_line->GetArgs()[i]);
    if (!AppendMatchingPaths(pattern, &trace_file_paths_)) {
      LOG(ERROR) << "Found no files matching '" << pattern.value() << "'.";
      return Usage(command_line, "");
    }
  }

  // Check if we are in random order mode. Look for and parse --seed.
  if (command_line->HasSwitch(kSeed)) {
    if (!trace_file_paths_.empty()) {
      return Usage(command_line,
                   "Trace files are not accepted in random order mode.");
    }
    std::string seed_str(command_line->GetSwitchValueASCII(kSeed));
    int tmp_seed = 0;
    if (seed_str.empty() || !base::StringToInt(seed_str, &tmp_seed)) {
      return Usage(command_line, "Invalid seed value.");
    }
    seed_ = tmp_seed;
    mode_ = kRandomOrderMode;
  }

  // Parse the list-dead-code switch.
  if (command_line->HasSwitch(kListDeadCode)) {
    if (mode_ != kInvalidMode) {
      LOG(ERROR) << "--" << kListDeadCode << " and --" << kSeed << "=N are "
                 << "mutually exclusive.";
      return false;
    }
    mode_ = kDeadCodeFinderMode;
  }

  // If we haven't found anything to over-ride the default mode (linear order),
  // then the default it is.
  if (mode_ == kInvalidMode)
    mode_ = kLinearOrderMode;

  // We do not accept trace file paths in random order mode.
  if (mode_ == kRandomOrderMode && !trace_file_paths_.empty()) {
    return Usage(command_line,
                 "Trace files are not accepted in random order mode.");
  }

  // We only accept a basic-block entry count file in linear order mode, and
  // we require the input image path when we do so.
  if (!bb_entry_count_file_path_.empty()) {
    if (mode_ != kLinearOrderMode) {
      return Usage(command_line,
                   "A basic-block entry counts file is only accepted in linear "
                   "order mode.");
    }
    if (input_image_path_.empty()) {
      return Usage(command_line,
                   "The input image is required for basic-block level "
                   "optimization.");
    }
  }

  // If we get here then the command-line switches were valid.
  return true;
}

bool ReorderApp::SetUp() {
  switch (mode_) {
    case kLinearOrderMode:
      order_generator_.reset(new LinearOrderGenerator());
      return true;

    case kRandomOrderMode:
      order_generator_.reset(new RandomOrderGenerator(seed_));
      return true;

    case kDeadCodeFinderMode:
      order_generator_.reset(new DeadCodeFinder());
      return true;
  }

  NOTREACHED();
  return false;
}

int ReorderApp::Run() {
  pe::PEFile input_image;
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  Reorderer::Order order;
  Reorderer reorderer(input_image_path_,
                      instrumented_image_path_,
                      trace_file_paths_,
                      flags_);

  // Generate a block-level ordering.
  if (!reorderer.Reorder(order_generator_.get(),
                         &order,
                         &input_image,
                         &image_layout)) {
    LOG(ERROR) << "Reorder failed.";
    return 1;
  }

  // Basic-block optimize the resulting order if there is an entry count file.
  if (mode_ == kLinearOrderMode && !bb_entry_count_file_path_.empty()) {
    pe::PEFile::Signature signature;
    input_image.GetSignature(&signature);
    if (!OptimizeBasicBlocks(signature, image_layout, &order)) {
      LOG(ERROR) << "Basic-block optimization failed.";
      return 1;
    }
  }

  // Serialize the order to JSON.
  if (!order.SerializeToJSON(input_image, output_file_path_, pretty_print_)) {
    LOG(ERROR) << "Unable to output order.";
    return 1;
  }

  // We were successful.
  return 0;
}

bool ReorderApp::Usage(const CommandLine* cmd_line,
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

bool ReorderApp::OptimizeBasicBlocks(const pe::PEFile::Signature& signature,
                                     const pe::ImageLayout& image_layout,
                                     Reorderer::Order* order) {
  DCHECK(order != NULL);

  LOG(INFO) << "Performing basic block ordering.";

  // Load the basic-block entry count data.
  ModuleIndexedFrequencyMap module_entry_count_map;
  IndexedFrequencyDataSerializer serializer;
  if (!serializer.LoadFromJson(bb_entry_count_file_path_,
                               &module_entry_count_map)) {
    LOG(ERROR) << "Failed to load basic-block entry count data";
    return false;
  }

  const IndexedFrequencyInformation* entry_counts = NULL;
  if (!FindIndexedFrequencyInfo(signature,
                                module_entry_count_map,
                                &entry_counts)) {
    LOG(ERROR) << "Failed to find entry count vector for '"
               << signature.path << "'.";
    return false;
  }

  // Optimize the ordering at the basic-block level.
  BasicBlockOptimizer optimizer;
  if (!optimizer.Optimize(image_layout, *entry_counts, order)) {
    LOG(ERROR) << "Failed to optimize basic-block ordering.";
    return false;
  }

  return true;
}

}  // namespace reorder
