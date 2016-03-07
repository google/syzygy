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

#ifndef SYZYGY_AGENT_COMMON_ENTRY_FRAME_H_
#define SYZYGY_AGENT_COMMON_ENTRY_FRAME_H_

#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {

// This structure is overlaid on the entry frame by the entry hook, to allow
// to the user to access and modify the entry frame.
struct EntryFrame {
  RetAddr retaddr;
  ArgumentWord args[4];
};

}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_ENTRY_FRAME_H_
