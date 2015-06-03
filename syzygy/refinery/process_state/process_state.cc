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

#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

ProcessState::ProcessState() {
}

ProcessState::~ProcessState() {
}

bool ProcessState::FindStackRecord(
    size_t thread_id,
    scoped_refptr<Record<Stack>>* record) {
  StackLayerPtr stack_layer;
  if (!FindLayer(&stack_layer))
    return false;

  for (StackRecordPtr stack : *stack_layer) {
    const Stack& stack_proto = stack->data();
    DCHECK(stack_proto.has_thread_info());
    DCHECK(stack_proto.thread_info().has_thread_id());
    if (stack_proto.thread_info().thread_id() == thread_id) {
      *record = stack;
      return true;
    }
  }

  return false;
}

}  // namespace refinery
