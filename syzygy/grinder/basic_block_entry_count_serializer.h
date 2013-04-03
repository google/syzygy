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
// Declares the BasicBlockEntryCountSerializer class.

#ifndef SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_SERIALIZER_H_
#define SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_SERIALIZER_H_

#include <map>
#include <vector>

#include "base/values.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {

// This class serializes and deserializes a basic_block_util::EntryCountMap,
// containing entry count information for one or more modules, to/from a JSON
// file.
//
// The JSON file has the following structure.
//
//     [
//       // Basic-block entry counts for module 1. Note that the module
//       // information refers to the original module, as opposed to the
//       // instrumented copy.
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
//         // Basic-block entry count pairs, encoded as pairs of
//         // [offset, count], where offset is the RVA to the first instruction
//         // byte of the basic block in the original image.
//         "entry_counts": [
//           [100, 10000],
//           [200, 123456]
//         ]
//       },
//       // Basic-block entry counts for module 2.
//       ...
//     ]
class BasicBlockEntryCountSerializer {
 public:
  typedef basic_block_util::ModuleEntryCountMap ModuleEntryCountMap;

  BasicBlockEntryCountSerializer();

  // Sets the pretty-printing status.
  void set_pretty_print(bool value) { pretty_print_ = value; }

  // Saves the given entry count map to a file at @p file_path.
  bool SaveAsJson(const ModuleEntryCountMap& entry_counts,
                  const base::FilePath& file_path);

  // Saves the given entry count map to a file previously opened for writing.
  bool SaveAsJson(const ModuleEntryCountMap& entry_counts,
                  FILE* file);

  // Populates an entry count map from a JSON file, given by @p file_path.
  bool LoadFromJson(const base::FilePath& file_path,
                    ModuleEntryCountMap* entry_counts);

 protected:
  // Populates an entry count map from JSON data. Exposed for unit-testing
  // purposes.
  bool PopulateFromJsonValue(const base::Value* json_value,
                             ModuleEntryCountMap* entry_counts);

  // If true, the JSON output will be pretty printed for easier human
  // consumption.
  bool pretty_print_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockEntryCountSerializer);
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_BASIC_BLOCK_ENTRY_COUNT_SERIALIZER_H_
