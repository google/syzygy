// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declares some constants that are used across ASan.

#ifndef SYZYGY_AGENT_ASAN_CONSTANTS_H_
#define SYZYGY_AGENT_ASAN_CONSTANTS_H_

namespace agent {
namespace asan {

// The ratio of shadow memory to actual memory. This governs the behaviour, size
// and alignment requirements of many ASan structures.
static const size_t kShadowRatioLog = 3;
static const size_t kShadowRatio = (1 << kShadowRatioLog);

// The size of a page on the OS.
extern const size_t kPageSize;

// The default sharding factor of the quarantine. This is used to give us linear
// access for random removal and insertion of elements into the quarantine.
static const size_t kQuarantineDefaultShardingFactor = 128;

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_CONSTANTS_H_
