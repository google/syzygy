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

#include "syzygy/agent/memprof/memory_profiler.h"

namespace agent {
namespace memprof {

MemoryProfiler::MemoryProfiler()
    : function_call_logger_(&session_, &segment_) {
}

bool MemoryProfiler::Init() {
  return trace::client::InitializeRpcSession(&session_, &segment_);
}

}  // namespace memprof
}  // namespace agent
