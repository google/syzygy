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
                     const TraceFileList& trace_files,
                     SimulationEventHandler* simulation)
    : module_path_(module_path),
      instrumented_path_(instrumented_path),
      trace_files_(trace_files),
      simulation_(simulation),
      parser_(NULL),
      pe_file_(),
      image_layout_(&block_graph_) {
  DCHECK(simulation_ != NULL);
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

void Simulator::OnProcessStarted(base::Time time,
                                 DWORD process_id,
                                 const TraceSystemInfo* data) {
  // Call the implementation of OnProcessStarted our simulator uses.
  DCHECK(simulation_ != NULL);

  if (data == NULL)
    simulation_->OnProcessStarted(time, 0);
  else
    simulation_->OnProcessStarted(time, data->system_info.dwPageSize);
}

void Simulator::OnFunctionEntry(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceEnterExitEventData* data) {
  DCHECK(playback_ != NULL);
  DCHECK(data != NULL);
  const BlockGraph::Block* block = playback_->FindFunctionBlock(
      process_id, data->function);

  if (block == NULL) {
    parser_->set_error_occurred(true);
    return;
  }

  // Call our simulation with the event data we have.
  DCHECK(simulation_ != NULL);
  simulation_->OnFunctionEntry(time, block->addr().value(), block->size());
}

void Simulator::OnBatchFunctionEntry(base::Time time,
                                     DWORD process_id,
                                     DWORD thread_id,
                                     const TraceBatchEnterData* data) {
  // Explode the batch event into individual function entry events.
  TraceEnterExitEventData new_data = {};
  for (size_t i = 0; i < data->num_calls; ++i) {
    new_data.function = data->calls[i].function;

    // Convert the tick count of this specific function to a base::Time
    // and call OnFunctionEntry with that value.
    LARGE_INTEGER big_timestamp = {};
    big_timestamp.QuadPart = data->calls[i].tick_count;
    base::Time start_time(base::Time::FromFileTime(
        *reinterpret_cast<FILETIME*>(&big_timestamp)));
    OnFunctionEntry(start_time, process_id, thread_id, &new_data);
  }
}

void Simulator::OnProcessEnded(base::Time time, DWORD process_id) {
}

void Simulator::OnFunctionExit(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
}

void Simulator::OnProcessAttach(base::Time time,
                                DWORD process_id,
                                DWORD thread_id,
                                const TraceModuleData* data) {
}

void Simulator::OnProcessDetach(base::Time time, DWORD process_id,
                                DWORD thread_id,
                                const TraceModuleData* data) {
}

void Simulator::OnThreadAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
}

void Simulator::OnThreadDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
}

void Simulator::OnInvocationBatch(base::Time time,
                                  DWORD process_id,
                                  DWORD thread_id,
                                  size_t num_batches,
                                  const TraceBatchInvocationInfo* data) {
}

} // namespace simulate
