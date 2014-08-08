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
// Decomposes an image multiple times while capturing timing information.

#include "syzygy/experimental/timed_decomposer/timed_decomposer_app.h"

#include <numeric>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "base/files/file_path.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/serialization.h"

namespace experimental {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "\n"
    "  A tool that performs multiple decompositions of a given input image\n"
    "  and reports the time taken individually and on average for each.\n"
    "\n"
    "Required parameters:\n"
    "  --image=IMAGE_FILE   The EXE or DLL to decompose.\n"
    "  --iterations=NUM     The number of times to decompose the image.\n"
    "\n"
    "Optional parameters:\n"
    "  --csv=PATH           The path to which CVS output should be written.\n";

bool WriteCsvFile(const base::FilePath& path,
                  const std::vector<double>& samples) {
  LOG(INFO) << "Writing samples information to '" << path.value() << "'.";
  base::ScopedFILE out_file(base::OpenFile(path, "wb"));
  if (out_file.get() == NULL) {
    LOG(ERROR) << "Failed to open " << path.value() << " for writing.";
    return false;
  }
  std::vector<double>::const_iterator it(samples.begin());
  DCHECK(it != samples.end());
  while (true) {
    fprintf(out_file.get(), "%f", *it);
    if (++it == samples.end())
      break;
    fprintf(out_file.get(), ", ");
  }
  fprintf(out_file.get(), "\n");
  return true;
}

}  // namespace

TimedDecomposerApp::TimedDecomposerApp()
    : common::AppImplBase("Timed Image Decomposer"),
      num_iterations_(0) {
}

void TimedDecomposerApp::PrintUsage(const base::FilePath& program,
                                    const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool TimedDecomposerApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help")) {
    PrintUsage(cmd_line->GetProgram(), "");
    return false;
  }

  image_path_ = cmd_line->GetSwitchValuePath("image");
  if (image_path_.empty()) {
    PrintUsage(cmd_line->GetProgram(), "Must specify '--image' parameter!");
    return false;
  }

  if (!base::StringToInt(
          cmd_line->GetSwitchValueNative("iterations"), &num_iterations_) ||
      num_iterations_ <= 0) {
    PrintUsage(cmd_line->GetProgram(), "Must specify '--iterations' >= 1!");
    return false;
  }

  csv_path_ = cmd_line->GetSwitchValuePath("csv");

  return true;
}

int TimedDecomposerApp::Run() {
  LOG(INFO) << "Processing \"" << image_path_.value() << "\".";

  DCHECK(!image_path_.empty());
  DCHECK_GT(0, num_iterations_);

  std::vector<double> samples;
  samples.reserve(num_iterations_);
  for (int i = 0; i < num_iterations_; ++i) {
    LOG(INFO) << "Starting iteration " << (i + 1) << ".";
    pe::PEFile pe_file;
    if (!pe_file.Init(image_path_))
      return 1;

    // Decompose the image.
    block_graph::BlockGraph block_graph;
    pe::ImageLayout image_layout(&block_graph);
    pe::Decomposer decomposer(pe_file);
    base::Time start(base::Time::NowFromSystemTime());
    if (!decomposer.Decompose(&image_layout))
      return 1;
    base::TimeDelta duration = base::Time::NowFromSystemTime() - start;
    samples.push_back(duration.InSecondsF());
    LOG(INFO) << "Iteration " << i << " took " << samples.back() << " seconds.";
  }

  double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
  double avg = sum / num_iterations_;

  LOG(INFO) << "Total decomposition time: " << sum << " seconds.";
  LOG(INFO) << "Average decomposition time : " << avg << " seconds.";

  if (!csv_path_.empty() && !WriteCsvFile(csv_path_, samples))
      return 1;

  return 0;
}

}  // namespace experimental
