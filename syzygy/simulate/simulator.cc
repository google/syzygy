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

#include "syzygy/simulate/simulator.h"

namespace simulate {

Simulator::Simulator(const FilePath& module_path,
                     const FilePath& instrumented_path,
                     const TraceFileList& trace_files)
    : module_path_(module_path),
      instrumented_path_(instrumented_path),
      trace_files_(trace_files),
      parser_(NULL),
      pe_file_(),
      image_layout_(&block_graph_) {
}

bool Simulator::ParseTraceFiles() {
  if (playback_ == NULL) {
    playback_.reset(
        new Playback(module_path_, instrumented_path_, trace_files_));
  }

  if (parser_ == NULL) {
    parser_.reset(new Parser());

    if (!parser_->Init(this)) {
      LOG(ERROR) << "Failed to initialize call trace parser.";
      // If we created the object that parser_ refers to, reset the pointer.
      // Otherwise we leave it as it was when we found it.
      parser_.reset();
      return false;
    }
  }

  if (!playback_->Init(&pe_file_, &image_layout_, parser_.get())) {
    playback_.reset();
    return false;
  }

  if (!parser_->Consume()) {
    playback_.reset();
    return false;
  }

  playback_.reset();

  return true;
}

} // namespace simulate
