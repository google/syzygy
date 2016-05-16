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

#ifndef SYZYGY_BARD_UNITTEST_UTIL_H_
#define SYZYGY_BARD_UNITTEST_UTIL_H_

#include <memory>

#include "gtest/gtest.h"
#include "syzygy/bard/event.h"
#include "syzygy/bard/trace_live_map.h"

namespace testing {

using bard::TraceLiveMap;

template <typename T>
void CheckTraceLiveMapContains(const TraceLiveMap<T>& const_trace_live_map,
                               T trace,
                               T live) {
  TraceLiveMap<T>& trace_live_map =
      const_cast<TraceLiveMap<T>&>(const_trace_live_map);

  T answer;
  EXPECT_TRUE(trace_live_map.GetLiveFromTrace(trace, &answer));
  EXPECT_EQ(live, answer);
  EXPECT_TRUE(trace_live_map.GetTraceFromLive(live, &answer));
  EXPECT_EQ(trace, answer);
}

template <typename T>
void CheckTraceLiveMapNotContain(const TraceLiveMap<T>& const_trace_live_map,
                                 T trace,
                                 T live) {
  TraceLiveMap<T>& trace_live_map =
      const_cast<TraceLiveMap<T>&>(const_trace_live_map);

  T answer;
  EXPECT_FALSE(trace_live_map.GetLiveFromTrace(trace, &answer));
  EXPECT_FALSE(trace_live_map.GetTraceFromLive(live, &answer));
}

template <typename Event>
void TestEventSerialization(const Event& original_data) {
  core::ByteVector bytes;

  core::ScopedOutStreamPtr out_stream;
  out_stream.reset(core::CreateByteOutStream(std::back_inserter(bytes)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  EXPECT_TRUE(Event::Save(&original_data, &out_archive));
  EXPECT_TRUE(out_archive.Flush());

  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(bytes.begin(), bytes.end()));
  core::NativeBinaryInArchive in_archive(in_stream.get());
  std::unique_ptr<Event> data_copy = std::move(Event::Load(&in_archive));
  EXPECT_NE(static_cast<Event*>(nullptr), data_copy.get());

  // Expect equality.
  EXPECT_TRUE(original_data.Equals(data_copy.get()));
}

}  // namespace testing

#endif  // SYZYGY_BARD_UNITTEST_UTIL_H_
