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
// An interface used to simulate block events.

#ifndef SYZYGY_SIMULATE_SIMULATION_EVENT_HANDLER_H_
#define SYZYGY_SIMULATE_SIMULATION_EVENT_HANDLER_H_

#include "base/time/time.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace simulate {

// This pure virtual interface handles the event dispatching of other
// Simulation classes. It's supposed to be used by Simulator, and each
// On... function to be the rough equivalent to another function
// in ParseEventHandler.
class SimulationEventHandler {
 public:
  // Issued once, prior to the first OnFunctionEntry event in each
  // instrumented module.
  // @param time The entry time of this process.
  // @param default_page_size The page size to be used, or 0 to use a default
  // page size.
  virtual void OnProcessStarted(base::Time time, size_t default_page_size) = 0;

  // Issued for all function entry traces.
  // @param time The entry time of this function.
  // @param block_start The first relative address of the code block.
  // @param block Information about the function block.
  virtual void OnFunctionEntry(
      base::Time time,
      const block_graph::BlockGraph::Block* block) = 0;

  // Serializes the data to JSON.
  // @param output The output FILE.
  // @param pretty_print Pretty printing on the JSON file.
  // @returns true on success, false on failure.
  virtual bool SerializeToJSON(FILE* output, bool pretty_print) = 0;
};

}  // namespace simulate

#endif  // SYZYGY_SIMULATE_SIMULATION_EVENT_HANDLER_H_
