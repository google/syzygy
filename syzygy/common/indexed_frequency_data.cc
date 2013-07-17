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

namespace common {

const uint32 kBasicBlockCoverageAgentId = 0xC05E4A6E;
const uint32 kBasicBlockEntryAgentId = 0xBBEABBEA;
const uint32 kJumpTableCountAgentId = 0x07AB1E0C;

// This should be incremented when incompatible changes are made to a tracing
// client.
const uint32 kBasicBlockFrequencyDataVersion = 1;
const uint32 kBranchFrequencyDataVersion = 1;
const uint32 kJumpTableFrequencyDataVersion = 1;

const char kBasicBlockRangesStreamName[] = "/Syzygy/BasicBlockRanges";

}  // namespace common
