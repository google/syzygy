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

#include "syzygy/simulate/page_fault_simulator.h"

#include "syzygy/core/json_file_writer.h"

namespace simulate {

PageFaultSimulator::PageFaultSimulator(const FilePath& module_path,
                                       const FilePath& instrumented_path,
                                       const TraceFileList& trace_files)
    : Simulator(module_path, instrumented_path, trace_files),
      fault_count_(0),
      page_size_(0),
      pages_per_code_fault_(kDefaultPagesPerCodeFault) {
}

void PageFaultSimulator::OnProcessStarted(base::Time time,
                                          DWORD process_id,
                                          const TraceSystemInfo* data) {
  // Set the page size if it wasn't set by the user yet.
  if (page_size_ == 0) {
    if (data == NULL)
      page_size_ = kDefaultPageSize;
    else
      page_size_ = data->system_info.dwPageSize;

    LOG(INFO) << "Page size set to " << page_size_;
  }
}

bool PageFaultSimulator::SerializeToJSON(FILE* output,
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
  for (; i != pages_.end(); i++) {
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

void PageFaultSimulator::OnFunctionEntry(base::Time time,
                                         DWORD process_id,
                                         DWORD thread_id,
                                         const TraceEnterExitEventData* data) {
  // Resolve the module in which the called function resides.
  AbsoluteAddress64 function_address = reinterpret_cast<AbsoluteAddress64>(
      data->function);

  const ModuleInformation* module_info =
      parser_->GetModuleInformation(process_id, function_address);

  // We should be able to resolve the instrumented module.
  if (module_info == NULL) {
    LOG(ERROR) << "Failed to resolve module for entry event (pid="
               << process_id << ", addr=0x" << data->function << ").";
    parser_->set_error_occurred(true);
    return;
  }

  // Convert the address to an RVA. We can only instrument 32-bit DLLs, so
  // we're sure that the following address conversion is safe.
  RelativeAddress rva(static_cast<uint32>(
      function_address - module_info->base_address));

  // Convert the address from one in the instrumented module to one in the
  // original module using the OMAP data.
  rva = pdb::TranslateAddressViaOmap(playback_->omap_to(), rva);

  // Get the block that this function call refers to.
  const BlockGraph::Block* block =
      image_layout_.blocks.GetBlockByAddress(rva);

  if (block == NULL) {
    LOG(ERROR) << "Unable to map " << rva << " to a block.";
    parser_->set_error_occurred(true);
    return;
  }
  if (block->type() != BlockGraph::CODE_BLOCK) {
    LOG(ERROR) << rva << " maps to a non-code block (" << block->name()
               << " in " << module_info->image_file_name << ").";
    parser_->set_error_occurred(true);
    return;
  }

  RelativeAddress block_addr;
  image_layout_.blocks.GetAddressOf(block, &block_addr);

  const size_t kStartIndex = block_addr.value() / page_size_;
  const size_t kEndIndex = (block_addr.value() + block->size() +
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

void PageFaultSimulator::OnBatchFunctionEntry(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceBatchEnterData* data) {
  // Explode the batch event into individual function entry events.
  TraceEnterExitEventData new_data = {};
  for (size_t i = 0; i < data->num_calls; ++i) {
    new_data.function = data->calls[i].function;
    OnFunctionEntry(time, process_id, thread_id, &new_data);
  }
}

} // namespace simulate
