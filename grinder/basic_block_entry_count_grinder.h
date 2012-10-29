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
// Declares the BasicBlockEntryCountGrinder class, which processes trace files
// containing basic-block frequency data and outputs a summary JSON file.

#ifndef SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_GRINDER_H_
#define SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_GRINDER_H_

#include <map>
#include <vector>

#include "base/values.h"
#include "syzygy/grinder/basic_block_entry_count_serializer.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {

// This class processes trace files containing basic-block frequency data,
// populating an EntryCountMap with summary entry counts, and
// generating a JSON output file.
//
// See basic_block_entry_count_serializer.h for the resulting JSON structure.
//
// The JSON output will be pretty printed if --pretty-print is included in the
// command line passed to ParseCommandLine().
class BasicBlockEntryCountGrinder : public GrinderInterface {
 public:
  BasicBlockEntryCountGrinder();

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual void SetParser(Parser* parser) OVERRIDE;
  virtual bool Grind() OVERRIDE;
  virtual bool OutputData(FILE* file) OVERRIDE;
  // @}

  // @name ParseEventHandler overrides.
  // @{
  virtual void OnBasicBlockFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceBasicBlockFrequencyData* data) OVERRIDE;
  // @}

  // @returns a map from ModuleInformation records to bb entry counts.
  const basic_block_util::ModuleEntryCountMap& entry_count_map() const {
    return entry_count_map_;
  }

 protected:
  typedef basic_block_util::RelativeAddressRangeVector
      RelativeAddressRangeVector;
  typedef basic_block_util::ModuleInformation ModuleInformation;
  typedef basic_block_util::ModuleIdentityComparator ModuleIdentityComparator;

  // The data we store per encountered instrumented module.
  struct InstrumentedModuleInformation {
    // The basic block ranges allow us to resolve the ordinal basic block
    // IDs to relative offsets in the original image.
    RelativeAddressRangeVector block_ranges;

    // The module information for the original image is what goes into the
    // ModuleEntryCount map.
    ModuleInformation original_module;
  };

  typedef std::map<ModuleInformation,
                   InstrumentedModuleInformation,
                   ModuleIdentityComparator> InstrumentedModuleMap;

  // This method does the actual updating of the entry counts on receipt
  // of basic-block frequency data. It is implemented separately from the
  // main hook for unit-testing purposes.
  // @param module_info the module whose basic-block entries are being counted.
  // @param data the basic-block entry counts being reported.
  void UpdateBasicBlockEntryCount(
      const InstrumentedModuleInformation& module_info,
      const TraceBasicBlockFrequencyData* data);

  // Finds or creates a new entry for an encountered instrumented module.
  // @param module_info the module info for the instrumented module encountered.
  // @returns the initialized instrumented module on success, or NULL on failure
  //     to locate the instrumented module or initialize the module information.
  const InstrumentedModuleInformation* FindOrCreateInstrumentedModule(
      const ModuleInformation* module_info);

  // Stores the summarized basic-block entry counts for each module encountered.
  basic_block_util::ModuleEntryCountMap entry_count_map_;

  // Stores the basic block ID maps for each module encountered.
  InstrumentedModuleMap instrumented_modules_;

  // Used to save the JSON output to a file. Also tracks the pretty-printing
  // status of this grinder.
  BasicBlockEntryCountSerializer serializer_;

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;

  // Set to true if any call to OnBasicBlockFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockEntryCountGrinder);
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_GRINDER_H_
