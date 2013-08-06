// Copyright 2013 Google Inc. All Rights Reserved.
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
// Implements the one non-trivial dlist operation.

#include "syzygy/agent/common/dlist.h"

#include "base/logging.h"

BOOL IsNodeOnList(LIST_ENTRY* list_head, LIST_ENTRY* entry) {
  DCHECK(list_head != NULL);
  DCHECK(entry != NULL);

  LIST_ENTRY* curr = list_head->Flink;
  for (; curr != list_head; curr = curr->Flink) {
    if (curr == entry)
      return TRUE;
  }

  return FALSE;
}
