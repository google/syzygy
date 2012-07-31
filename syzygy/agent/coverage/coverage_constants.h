// Copyright 2012 Google Inc.
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
// Declares constants related to the code coverage client.

#ifndef SYZYGY_AGENT_COVERAGE_COVERAGE_CONSTANTS_H_
#define SYZYGY_AGENT_COVERAGE_COVERAGE_CONSTANTS_H_

#include <windows.h>

#include "base/basictypes.h"

namespace agent {
namespace coverage {

// The coverage client 'magic'.
extern const uint32 kCoverageClientMagic;

// The coverage client version.
extern const uint32 kCoverageClientVersion;

// This is the name of the data section added to an instrumented image by
// the coverage client.
extern const char kCoverageClientDataSectionName[];

// The characteristics given to the coverage instrumentation section.
extern const DWORD kCoverageClientDataSectionCharacteristics;

}  // namespace coverage
}  // namespace agent

#endif  // SYZYGY_AGENT_COVERAGE_COVERAGE_CONSTANTS_H_
