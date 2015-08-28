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

#include "syzygy/grinder/grinders/mem_replay_grinder.h"

#include "base/strings/string_util.h"
#include "gtest/gtest.h"

namespace grinder {
namespace grinders {

namespace {

class TestMemReplayGrinder : public MemReplayGrinder {
 public:
  using MemReplayGrinder::process_id_enum_map_;
  using MemReplayGrinder::missing_events_;

  using MemReplayGrinder::LoadAsanFunctionNames;
};

}  // namespace

TEST(MemReplayGrinderTest, TestTableEntry) {
  const char kDummyFunctionName[] = "asan_HeapAlloc";
  char buffer[FIELD_OFFSET(TraceFunctionNameTableEntry, name) +
              arraysize(kDummyFunctionName)] = {};
  TraceFunctionNameTableEntry* data =
      reinterpret_cast<TraceFunctionNameTableEntry*>(buffer);

  data->function_id = 37;
  data->name_length = arraysize(kDummyFunctionName);
  base::snprintf(data->name, data->name_length, kDummyFunctionName);

  TestMemReplayGrinder grinder;

  grinder.LoadAsanFunctionNames();
  grinder.OnFunctionNameTableEntry(base::Time::Now(), 1, data);

  EXPECT_EQ(bard::EventInterface::EventType::kHeapAllocEvent,
            grinder.process_id_enum_map_[std::make_pair(1, 37)]);
}

TEST(MemReplayGrinderTest, TestInvalidTableEntry) {
  const char kDummyFunctionName[] = "DummyFunctionName";
  char buffer[FIELD_OFFSET(TraceFunctionNameTableEntry, name) +
              arraysize(kDummyFunctionName)] = {};
  TraceFunctionNameTableEntry* data =
      reinterpret_cast<TraceFunctionNameTableEntry*>(buffer);

  data->function_id = 37;
  data->name_length = arraysize(kDummyFunctionName);
  base::snprintf(data->name, data->name_length, kDummyFunctionName);

  TestMemReplayGrinder grinder;

  grinder.LoadAsanFunctionNames();
  grinder.OnFunctionNameTableEntry(base::Time::Now(), 1, data);

  EXPECT_EQ(1u, grinder.missing_events_.size());
  EXPECT_NE(grinder.missing_events_.end(),
            grinder.missing_events_.find(kDummyFunctionName));
}

}  // namespace grinders
}  // namespace grinder
