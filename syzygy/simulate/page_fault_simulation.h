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
// This file provides the PageFaultSimulation class.

#ifndef SYZYGY_SIMULATE_PAGE_FAULT_SIMULATION_H_
#define SYZYGY_SIMULATE_PAGE_FAULT_SIMULATION_H_

#include "syzygy/simulate/simulation_event_handler.h"
#include "syzygy/trace/parse/parser.h"

namespace simulate {

// An implementation of SimulationEventHandler. PageFaultSimulation simply
// counts the total number of page-faults that happen in the specified
// functions. Sample usage:
//
// PageFaultSimulation simulation;
//
// simulation.set_page_size(0x2000);
// simulation.set_pages_per_code_fault(10);
// simulation.OnProcessStarted(time, 0);
// simulation.OnFunctionEntry(time, 5);
// simulation.OnFunctionEntry(time, 200);
// simulator.SerializeToJSON(file, pretty_print);
//
// If the pages per code fault are not set, then the default value of
// 8 is used.
//
// If the page size is not set, then it's deduced from the trace file data
// or, if that's not possible, it's set to the default value of 0x1000 (4 KB).
class PageFaultSimulation : public SimulationEventHandler {
 public:
  typedef block_graph::BlockGraph::Block Block;
  typedef std::set<uint32_t> PageSet;

  // The default page size, in case neither the user nor the system
  // provide one.
  static const size_t kDefaultPageSize = 0x1000;

  // The default number of pages loaded on each code-fault.
  static const size_t kDefaultPagesPerCodeFault = 8;

  // Constructs a new PageFaultSimulation instance.
  PageFaultSimulation();

  // @name Accessors
  // @{
  const PageSet& pages() const { return pages_; }
  size_t fault_count() const { return fault_count_; }
  size_t page_size() const { return page_size_; }
  size_t pages_per_code_fault() const { return pages_per_code_fault_; }
  // @}

  // @name Mutators
  // @{
  void set_page_size(size_t page_size) {
    DCHECK(page_size > 0);
    page_size_ = page_size;
  }
  void set_pages_per_code_fault(size_t pages_per_code_fault) {
    DCHECK(pages_per_code_fault > 0);
    pages_per_code_fault_ = pages_per_code_fault;
  }
  // @}

  // @name SimulationEventHandler implementation
  // @{
  // Sets the initial page size, if it's not set already.
  void OnProcessStarted(base::Time time, size_t default_page_size) override;

  // Registers the page faults, given a certain code block.
  void OnFunctionEntry(base::Time time, const Block* block) override;

  // The serialization consists of a single dictionary containing
  // the block number of each block that pagefaulted.
  bool SerializeToJSON(FILE* output, bool pretty_print) override;
  // @}

 protected:
  // A set which contains the block number of the pages that
  // were faulted in the trace files.
  PageSet pages_;

  // The total number of page-faults detected.
  size_t fault_count_;

  // The size of each page, in bytes. If not set, PageFaultSimulator will
  // try to load the system value, or uses kDefaultPageSize
  // if it's unavailable.
  size_t page_size_;

  // The number of pages each code-fault loads. If not set,
  // PageFaultSimulator uses kDefaultPagesPerFault.
  size_t pages_per_code_fault_;
};

}  // namespace simulate

#endif  // SYZYGY_SIMULATE_PAGE_FAULT_SIMULATION_H_
