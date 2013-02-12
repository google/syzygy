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
// Declares constants used by the various pieces of the instrumentation and
// trace agent's that work with basic-blocks. For example, this might include
// a coverage client and instrumentation (a single on/off value for whether or
// not a basic-block was entered) or a thread-aware basic-block entry counting
// client and instrumentation.

#ifndef SYZYGY_COMMON_BASIC_BLOCK_FREQUENCY_DATA_H_
#define SYZYGY_COMMON_BASIC_BLOCK_FREQUENCY_DATA_H_

#include <windows.h>

#include "base/basictypes.h"
#include "syzygy/common/indexed_frequency_data.h"

namespace common {

typedef IndexedFrequencyData BasicBlockFrequencyData;

// The basic-block coverage agent ID.
extern const uint32 kBasicBlockCoverageAgentId;

// The basic-block entry counting agent ID.
extern const uint32 kBasicBlockEntryAgentId;

// The basic-block trace agent version.
extern const uint32 kBasicBlockFrequencyDataVersion;

// The name of the basic-block ranges stream added to the PDB by
// any instrumentation employing basic-block trace data.
extern const char kBasicBlockRangesStreamName[];

}  // namespace common

#endif  // SYZYGY_COMMON_BASIC_BLOCK_FREQUENCY_DATA_H_
