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
//
// An implementation of Simulator. PageFaultSimulator simply counts the total
// number of page-faults that happen in the specified trace file. Sample usage:
//
// PageFaultSimulator simulator(module_dll,
//                              instrumented_dll,
//                              trace_files);
// simulator.set_page_size(0x2000);
// simulator.set_pages_per_code_fault(10);
// simulator.ParseTraceFiles();
// simulator.SerializeToJSON(file, pretty_print);

#ifndef SYZYGY_SIMULATE_PAGE_FAULT_SIMULATOR_H_
#define SYZYGY_SIMULATE_PAGE_FAULT_SIMULATOR_H_

#include "syzygy/simulate/simulator.h"

namespace simulate {

class PageFaultSimulator : public Simulator {
 public:
  typedef std::set<uint32> PageSet;

  // The default page size, in case neither the user nor the system
  // provide one.
  static const DWORD kDefaultPageSize = 0x1000;

  // The default number of pages loaded on each code-fault.
  static const size_t kDefaultPagesPerCodeFault = 8;

  // Construct a new PageFaultSimulator instance.
  // @param module_path The path of the module dll.
  // @param instrumented_path The path of the instrumented dll.
  // @param trace_files A list of trace files to analyze.
  PageFaultSimulator(const FilePath& module_path,
                     const FilePath& instrumented_path,
                     const TraceFileList& trace_files);

  // @name Accessors
  // @{
  const PageSet& pages() const { return pages_; }
  size_t fault_count() const { return fault_count_; }
  DWORD page_size() const { return page_size_; }
  size_t pages_per_code_fault() const { return pages_per_code_fault_; }
  // @}

  // @name Mutators
  // @{
  void set_page_size(DWORD page_size) { page_size_ = page_size; }
  void set_pages_per_code_fault(size_t pages_per_code_fault) {
    pages_per_code_fault_ = pages_per_code_fault;
  }
  // @}

  // Serializes the data to JSON.
  // The serialization consists of a single dictionary containing
  // the block number of each block that pagefaulted.
  // @param output The output FILE.
  // @param pretty_print Pretty printing on the JSON file.
  // @returns true on success, false on failure.
  bool SerializeToJSON(FILE* output, bool pretty_print);

 protected:
  typedef core::RelativeAddress RelativeAddress;
  typedef trace::parser::ModuleInformation ModuleInformation;
  typedef uint64 AbsoluteAddress64;

  // @name ParseEventHandler implementation
  // @{
  void OnProcessStarted(base::Time time,
                        DWORD process_id,
                        const TraceSystemInfo* data) OVERRIDE;
  void OnFunctionEntry(base::Time time,
                       DWORD process_id,
                       DWORD thread_id,
                       const TraceEnterExitEventData* data) OVERRIDE;
  void OnBatchFunctionEntry(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const TraceBatchEnterData* data) OVERRIDE;
  // @}

  // A set which contains the block number of the pages that
  // were faulted in the trace files.
  PageSet pages_;

  // The total number of page-faults detected.
  size_t fault_count_;

  // The size of each page, in bytes. If not set, PageFaultSimulator will
  // try to load the system value, or uses kDefaultPageSize
  // if it's unavailable.
  DWORD page_size_;

  // The number of pages each code-fault loads. If not set,
  // PageFaultSimulator uses kDefaultPagesPerFault.
  size_t pages_per_code_fault_;
};

} // namespace simulate

#endif  // SYZYGY_SIMULATE_PAGE_FAULT_SIMULATOR_H_
