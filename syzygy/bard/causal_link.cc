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

#include "syzygy/bard/causal_link.h"

namespace bard {

CausalLink::CausalLink() : event_(true, false) {
}

void CausalLink::Reset() {
  event_.Reset();
}

void CausalLink::Signal() {
  event_.Signal();
}

bool CausalLink::IsSignaled() {
  return event_.IsSignaled();
}

void CausalLink::Wait() {
  event_.Wait();
}

bool CausalLink::TimedWait(const base::TimeDelta& max_time) {
  return event_.TimedWait(max_time);
}

}  // namespace bard
