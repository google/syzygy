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
// Declares some constants that are used across Asan.

#ifndef SYZYGY_AGENT_ASAN_CONSTANTS_H_
#define SYZYGY_AGENT_ASAN_CONSTANTS_H_

namespace agent {
namespace asan {

// The ratio of shadow memory to actual memory. This governs the behaviour, size
// and alignment requirements of many Asan structures.
static const size_t kShadowRatioLog = 3;
static const unsigned kShadowRatio = (1 << kShadowRatioLog);

// Expected page sizes and allocation granularities. Some usages of these are
// at compile time, thus we need accessible constants.
static const size_t kUsualPageSize = 4096;
static const size_t kUsualAllocationGranularity = 64 * 1024;

// The default sharding factor of the quarantine. This is used to give us linear
// access for random removal and insertion of elements into the quarantine.
static const size_t kQuarantineDefaultShardingFactor = 128;

// @returns the size of a page on the OS (usually 4KB).
// @note Declaring this as a constant might result in an initialization order
//     fiasco.
size_t GetPageSize();

// @returns the allocation granularity of the OS (usually 64KB).
// @note Declaring this as a constant might result in an initialization order
//     fiasco.
size_t GetAllocationGranularity();

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_CONSTANTS_H_
