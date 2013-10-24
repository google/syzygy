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

#include "syzygy/simulate/heat_map_simulation.h"

#include <functional>

namespace simulate {

HeatMapSimulation::HeatMapSimulation()
    : time_slice_usecs_(kDefaultTimeSliceSize),
      memory_slice_bytes_(kDefaultMemorySliceSize),
      max_time_slice_usecs_(0),
      max_memory_slice_bytes_(0),
      output_individual_functions_(false) {
}

bool HeatMapSimulation::TimeSlice::PrintJSONFunctions(
    core::JSONFileWriter& json_file,
    const HeatMapSimulation::TimeSlice::FunctionMap& functions) {
  typedef std::pair<uint32, base::StringPiece> QtyNamePair;
  std::vector<QtyNamePair> ordered_functions(functions.size());

  FunctionMap::const_iterator functions_iter = functions.begin();
  uint32 i = 0;
  for (; functions_iter != functions.end(); ++functions_iter, ++i) {
    ordered_functions[i] = QtyNamePair(functions_iter->second,
                                       functions_iter->first);
  }
  std::sort(ordered_functions.begin(),
            ordered_functions.end(),
            std::greater<QtyNamePair>());

  if (!json_file.OutputKey("functions") ||
      !json_file.OpenList())
    return false;

  for (uint32 i = 0; i < ordered_functions.size(); ++i) {
    if (!json_file.OpenDict() ||
        !json_file.OutputKey("name") ||
        !json_file.OutputString(ordered_functions[i].second.data()) ||
        !json_file.OutputKey("quantity") ||
        !json_file.OutputInteger(ordered_functions[i].first) ||
        !json_file.CloseDict())
      return false;
  }

  if (!json_file.CloseList())
    return false;

  return true;
}

bool HeatMapSimulation::SerializeToJSON(FILE* output, bool pretty_print) {
  typedef TimeSlice::FunctionMap FunctionMap;

  DCHECK(output != NULL);

  core::JSONFileWriter json_file(output, pretty_print);

  if (!json_file.OpenDict() ||
      !json_file.OutputKey("time_slice_usecs") ||
      !json_file.OutputInteger(time_slice_usecs_) ||
      !json_file.OutputKey("memory_slice_bytes") ||
      !json_file.OutputInteger(memory_slice_bytes_) ||
      !json_file.OutputKey("max_time_slice_usecs") ||
      !json_file.OutputInteger(max_time_slice_usecs_) ||
      !json_file.OutputKey("max_memory_slice_bytes") ||
      !json_file.OutputInteger(max_memory_slice_bytes_) ||
      !json_file.OutputKey("time_slice_list") ||
      !json_file.OpenList()) {
    return false;
  }

  TimeMemoryMap::const_iterator time_memory_iter = time_memory_map_.begin();
  for (; time_memory_iter != time_memory_map_.end(); ++time_memory_iter) {
    time_t time = time_memory_iter->first;
    uint32 total = time_memory_iter->second.total();
    const TimeSlice& time_slice = time_memory_iter->second;

    if (!json_file.OpenDict() ||
        !json_file.OutputKey("timestamp") ||
        !json_file.OutputInteger(time) ||
        !json_file.OutputKey("total_memory_slices") ||
        !json_file.OutputInteger(total) ||
        !json_file.OutputKey("memory_slice_list") ||
        !json_file.OpenList()) {
      return false;
    }

    TimeSlice::MemorySliceMap::const_iterator slices_iter =
        time_slice.slices().begin();

    for (; slices_iter != time_slice.slices().end(); ++slices_iter) {
      if (!json_file.OpenDict() ||
          !json_file.OutputKey("memory_slice") ||
          !json_file.OutputInteger(slices_iter->first) ||
          !json_file.OutputKey("quantity") ||
          !json_file.OutputInteger(slices_iter->second.total))
        return false;

      if (output_individual_functions_) {
        if (!TimeSlice::PrintJSONFunctions(json_file,
                                           slices_iter->second.functions))
          return false;
      }

      if (!json_file.CloseDict())
        return false;
    }

    if (!json_file.CloseList() ||
        !json_file.CloseDict())
      return false;
  }

  if (!json_file.CloseList() ||
      !json_file.CloseDict())
    return false;

  return json_file.Finished();
}

void HeatMapSimulation::OnProcessStarted(base::Time time,
                                         size_t /*default_page_size*/) {
  // Set the entry time of this process.
  process_start_time_ = time;
}

void HeatMapSimulation::OnFunctionEntry(base::Time time,
                                        const Block* block) {
  // Get the time when this function was called since the process start.
  time_t relative_time = (time - process_start_time_).InMicroseconds();

  // Since we will insert to a map many TimeSlices with the same entry time,
  // we can pass RegisterFunction a reference to the TimeSlice in the map.
  // This way, RegisterFunction doesn't have to search for that position
  // every time it gets called and the time complexity gets reduced
  // in a logarithmic scale.
  TimeSliceId time_slice = relative_time / time_slice_usecs_;
  TimeSlice& slice = time_memory_map_[time_slice];

  max_time_slice_usecs_ = std::max(max_time_slice_usecs_, time_slice);

  DCHECK(block != NULL);
  DCHECK(memory_slice_bytes_ != 0);
  const uint32 block_start = block->addr().value();
  const uint32 size = block->size();
  const std::string& name = block->name();

  const uint32 first_slice = block_start / memory_slice_bytes_;
  const uint32 last_slice = (block_start + size - 1) / memory_slice_bytes_;
  if (first_slice == last_slice) {
    // This function fits in a single memory slice. Add it to our time slice.
    slice.AddSlice(first_slice, name, size);
  } else {
    // This function takes several memory slices. Add the first and last
    // slices to our time slice only with the part of the slice they use,
    // and then loop through the rest and add the whole slices.
    const uint32 leading_bytes =
        memory_slice_bytes_ - block_start % memory_slice_bytes_;

    const uint32 trailing_bytes =
        ((block_start + size - 1 + memory_slice_bytes_) %
            memory_slice_bytes_) + 1;

    slice.AddSlice(first_slice, name, leading_bytes);
    slice.AddSlice(last_slice, name, trailing_bytes);

    const uint32 kStartIndex = block_start / memory_slice_bytes_ + 1;
    const uint32 kEndIndex = (block_start + size - 1) / memory_slice_bytes_;

    for (uint32 i = kStartIndex; i < kEndIndex; i++)
      slice.AddSlice(i, name, memory_slice_bytes_);
  }

  max_memory_slice_bytes_ = std::max(max_memory_slice_bytes_, last_slice);
}

}  // namespace simulate
