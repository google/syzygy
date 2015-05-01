// Copyright 2013 Google Inc. All Rights Reserved.
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
// Declares the IndexedFrequencyDataGrinder class, which processes trace files
// containing indexed frequencies data and outputs a summary JSON file.

#ifndef SYZYGY_GRINDER_GRINDERS_INDEXED_FREQUENCY_DATA_GRINDER_H_
#define SYZYGY_GRINDER_GRINDERS_INDEXED_FREQUENCY_DATA_GRINDER_H_

#include <map>
#include <vector>

#include "base/values.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"
#include "syzygy/grinder/indexed_frequency_data_serializer.h"

namespace grinder {
namespace grinders {

// This class processes trace files containing branch frequency data, populating
// an IndexedFrequencyMap with summary frequencies, and generating a JSON
// output file.
//
// See indexed_frequency_data_serializer.h for the resulting JSON structure.
//
// The JSON output will be pretty printed if --pretty-print is included in the
// command line passed to ParseCommandLine().
class IndexedFrequencyDataGrinder : public GrinderInterface {
 public:
  typedef basic_block_util::ModuleIndexedFrequencyMap ModuleIndexedFrequencyMap;

  IndexedFrequencyDataGrinder();

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const base::CommandLine* command_line) override;
  virtual void SetParser(Parser* parser) override;
  virtual bool Grind() override;
  virtual bool OutputData(FILE* file) override;
  // @}

  // @name ParseEventHandler overrides.
  // @{
  // Override of the OnIndexedFrequency callback.
  // NOTE: This only process TraceIndexedFrequencyData records of the
  //    appropriate type (bbentry, branch and coverage).
  virtual void OnIndexedFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceIndexedFrequencyData* data) override;
  // @}

  // @returns a map from ModuleInformation records to basic block frequencies.
  const ModuleIndexedFrequencyMap& frequency_data_map() const {
    return frequency_data_map_;
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
    // IndexedFrequencyMap map.
    ModuleInformation original_module;
  };

  typedef std::map<ModuleInformation,
                   InstrumentedModuleInformation,
                   ModuleIdentityComparator> InstrumentedModuleMap;

  // This method does the actual updating of the frequencies on receipt
  // of basic-block frequency data. It is implemented separately from the
  // main hook for unit-testing purposes.
  // @param module_info the module whose basic-block frequencies are being
  //     counted.
  // @param data the basic-block frequencies being reported. The data type of
  //     this record is expected to be a basic-blocks data frequencies.
  void UpdateBasicBlockFrequencyData(
      const InstrumentedModuleInformation& module_info,
      const TraceIndexedFrequencyData* data);

  // Finds or creates a new entry for an encountered instrumented module.
  // @param module_info the module info for the instrumented module encountered.
  // @returns the initialized instrumented module on success, or NULL on failure
  //     to locate the instrumented module or initialize the module information.
  const InstrumentedModuleInformation* FindOrCreateInstrumentedModule(
      const ModuleInformation* module_info);

  // Stores the summarized basic-block frequencies for each module encountered.
  ModuleIndexedFrequencyMap frequency_data_map_;

  // Stores the basic block ID maps for each module encountered.
  InstrumentedModuleMap instrumented_modules_;

  // Used to save the JSON output to a file. Also tracks the pretty-printing
  // status of this grinder.
  IndexedFrequencyDataSerializer serializer_;

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;

  // Set to true if any call to OnIndexedFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;

 private:
  DISALLOW_COPY_AND_ASSIGN(IndexedFrequencyDataGrinder);
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_INDEXED_FREQUENCY_DATA_GRINDER_H_
