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

#include "syzygy/agent/common/dlist.h"

#include "gtest/gtest.h"

TEST(DListTest, IsNodeOnList) {
  LIST_ENTRY list;
  InitializeListHead(&list);

  LIST_ENTRY node;
  EXPECT_FALSE(IsNodeOnList(&list, &node));

  LIST_ENTRY tail_node;
  InsertHeadList(&list, &tail_node);
  EXPECT_FALSE(IsNodeOnList(&list, &node));

  InsertHeadList(&list, &node);
  EXPECT_TRUE(IsNodeOnList(&list, &node));

  LIST_ENTRY head_node;
  InsertHeadList(&list, &head_node);
  EXPECT_TRUE(IsNodeOnList(&list, &node));

  RemoveEntryList(&node);
  EXPECT_FALSE(IsNodeOnList(&list, &node));
}
