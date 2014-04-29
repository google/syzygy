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

#include "syzygy/agent/common/agent.h"

#include <math.h>

namespace agent {
namespace common {

// This is to ensure that we have our own version of the CRT so as not to
// conflict with instrumented code.
#ifdef _DLL
#error Must be statically linked to the CRT.
#endif

void InitializeCrt() {
  // Disable SSE2 instructions. This is to ensure that our instrumentation
  // doesn't inadvertently tinker with SSE2 registers via the CRT, causing
  // instrumented SSE2 enabled instructions to screw up.
  const int kDisableSSE2 = 0;
  _set_SSE2_enable(kDisableSSE2);
}

}  // namespace common
}  // namespace agent
