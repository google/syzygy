// Copyright 2015 Google Inc. All Rights Reserved.
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
// Declares a minidump processor.

#ifndef SYZYGY_POIROT_MINIDUMP_PROCESSOR_H_
#define SYZYGY_POIROT_MINIDUMP_PROCESSOR_H_

#include "base/files/file_path.h"
#include "base/files/scoped_file.h"
#include "syzygy/crashdata/crashdata.h"

namespace poirot {

// The MinidumpProcessor reads the crash data embedded in a minidump and
// processes it.
class MinidumpProcessor {
 public:
  // Constructor.
  // @param input_minidump The minidump to process.
  explicit MinidumpProcessor(const base::FilePath& input_minidump);

  // Process the minidump.
  // @returns true on success, false otherwise.
  bool ProcessDump();

  // Convert the crash data contained in the minidump into a JSON
  // representation and dump it into |file|.
  // @param file A handle to the file in which the output should be printed.
  // @returns true on success, false otherwise.
  bool GenerateJsonOutput(FILE* file);

 protected:
  // The minidump to process.
  base::FilePath input_minidump_;

  // Indicates if the minidump has been processed.
  bool processed_;

  // The protobuf containing the crash data.
  crashdata::Value protobuf_value_;

  DISALLOW_COPY_AND_ASSIGN(MinidumpProcessor);
};

}  // namespace poirot

#endif  // SYZYGY_POIROT_MINIDUMP_PROCESSOR_H_
