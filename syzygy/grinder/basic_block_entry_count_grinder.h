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

#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {

// This class processes trace files containing basic-block frequency data and
// generates a summary JSON file.
//
// The JSON file has the following structure.
//
//     [
//       {
//         "metadata": {
//           "command_line": "\"foo.exe\"",
//           "creation_time": "Wed, 19 Sep 2012 17:33:52 GMT",
//           "toolchain_version": {
//             "major": 0,
//             "minor": 2,
//             "build": 7,
//             "patch": 0,
//             "last_change": "0"
//           },
//           "module_signature": {
//             "path": "C:\\foo\\bar.dll",
//             "base_address": 1904279552,
//             "module_size": 180224,
//             "module_time_date_stamp": "0x46F7885059FE32",
//             "module_checksum": "0x257AF"
//           }
//         },
//         "num_basic_blocks": 2933,
//         "entry_counts": [
//           9, 100, 0, 0, ...  // A total of num_basic_blocks entries.
//         ]
//       }
//     ]
class BasicBlockEntryCountGrinder : public GrinderInterface {
 public:
  typedef basic_block_util::ModuleInformation ModuleInformation;
  typedef uint64 CounterType;
  typedef std::vector<CounterType> EntryCountVector;
  typedef std::map<const ModuleInformation*, EntryCountVector> EntryCountMap;

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
  const EntryCountMap& entry_count_map() const { return entry_count_map_; }

 protected:
   // This method does the actual updating of the entry counts on receipt
   // of basic-block frequency data. It is implemented separately from the
   // main hook for unit-testing purposes.
   // @param module_info the module whose basic-block entries are being counted.
   // @param data the basic-block entry counts being reported.
   void UpdateBasicBlockEntryCount(const ModuleInformation* module_info,
                                   const TraceBasicBlockFrequencyData* data);

  // Stores the summarized basic-block entry counts, per module.
  EntryCountMap entry_count_map_;

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;

  // Set to true if any call to OnBasicBlockFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;

  // The JSON output will be pretty printed if this is true. This value is set
  // if --pretty-print is on the command line passed to ParseCommandLine().
  bool pretty_print_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockEntryCountGrinder);
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_GRINDER_H_
