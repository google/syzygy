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

#include "syzygy/common/indexed_frequency_data.h"

#include "base/logging.h"

namespace common {

const uint32_t kBasicBlockCoverageAgentId = 0xC05E4A6E;
const uint32_t kBasicBlockEntryAgentId = 0xBBEABBEA;
const uint32_t kJumpTableCountAgentId = 0x07AB1E0C;

// This should be incremented when incompatible changes are made to a tracing
// client.
const uint32_t kBasicBlockFrequencyDataVersion = 1;
const uint32_t kBranchFrequencyDataVersion = 1;
const uint32_t kJumpTableFrequencyDataVersion = 1;

const char kBasicBlockRangesStreamName[] = "/Syzygy/BasicBlockRanges";

// This must be kept in sync with IndexedFrequencyDataType::DataType.
const char* IndexedFrequencyDataTypeName[] = {
  NULL,
  "basic-block",
  "branch",
  "coverage",
  "jumptable",
};
static_assert(arraysize(IndexedFrequencyDataTypeName) ==
                  IndexedFrequencyData::MAX_DATA_TYPE,
              "Length mismatch");

bool IndexedFrequencyDataTypeToString(IndexedFrequencyData::DataType type,
                                      std::string* result) {
  DCHECK(result != NULL);
  if (type > IndexedFrequencyData::INVALID_DATA_TYPE &&
      type < IndexedFrequencyData::MAX_DATA_TYPE) {
    *result = IndexedFrequencyDataTypeName[type];
    return true;
  }

  return false;
}

bool ParseFrequencyDataType(const base::StringPiece& str,
                            IndexedFrequencyData::DataType* type) {
  DCHECK(type != NULL);
  for (int i = 1; i < IndexedFrequencyData::MAX_DATA_TYPE; ++i) {
    if (str.compare(IndexedFrequencyDataTypeName[i]) == 0) {
      *type = static_cast<IndexedFrequencyData::DataType>(i);
      return true;
    }
  }
  return false;
}

}  // namespace common
