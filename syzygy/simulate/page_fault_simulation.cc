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

#include "syzygy/simulate/page_fault_simulation.h"

#include "syzygy/core/json_file_writer.h"

namespace simulate {

PageFaultSimulation::PageFaultSimulation()
    : fault_count_(0),
      page_size_(0),
      pages_per_code_fault_(kDefaultPagesPerCodeFault) {
}

void PageFaultSimulation::OnProcessStarted(base::Time /*time*/,
                                           size_t default_page_size) {
  // Set the page size if it wasn't set by the user yet.
  if (page_size_ != 0)
    return;

  if (default_page_size != 0)
    page_size_ = default_page_size;
  else
    page_size_ = kDefaultPageSize;

  LOG(INFO) << "Page size set to " << page_size_;
}

bool PageFaultSimulation::SerializeToJSON(FILE* output,
                                          bool pretty_print) {
  DCHECK(output != NULL);
  core::JSONFileWriter json_file(output, pretty_print);

  // TODO(fixman): Report faulting addresses and times.
  if (!json_file.OpenDict() ||
      !json_file.OutputKey("page_size") ||
      !json_file.OutputInteger(page_size_) ||
      !json_file.OutputKey("pages_per_code_fault") ||
      !json_file.OutputInteger(pages_per_code_fault_) ||
      !json_file.OutputKey("fault_count") ||
      !json_file.OutputInteger(fault_count_) ||
      !json_file.OutputKey("loaded_pages") ||
      !json_file.OpenList()) {
    return false;
  }

  PageSet::const_iterator i = pages_.begin();
  for (; i != pages_.end(); ++i) {
    if (!json_file.OutputInteger(*i)) {
      return false;
    }
  }

  if (!json_file.CloseList() ||
      !json_file.CloseDict()) {
    return false;
  }

  DCHECK(json_file.Finished());
  return true;
}

void PageFaultSimulation::OnFunctionEntry(base::Time /*time*/,
                                          const Block* block) {
  DCHECK(block != NULL);
  DCHECK(page_size_ != 0);

  const uint32_t block_start = block->addr().value();
  const uint32_t block_size = block->size();
  const size_t kStartIndex = block_start / page_size_;
  const size_t kEndIndex = (block_start + block_size +
      page_size_ - 1) / page_size_;

  // Loop through all the pages in the block, and if it isn't already in memory
  // then simulate a code fault and load all the faulting pages in memory.
  for (size_t i = kStartIndex; i < kEndIndex; i++) {
    if (pages_.find(i) == pages_.end()) {
      fault_count_++;
      for (size_t j = 0; j < pages_per_code_fault_; j++) {
        pages_.insert(i + j);
      }
    }
  }
}

}  // namespace simulate
