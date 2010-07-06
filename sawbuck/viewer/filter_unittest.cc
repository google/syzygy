// Copyright 2010 Google Inc.
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
#include "sawbuck/viewer/filter.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "sawbuck/viewer/mock_log_view_interfaces.h"

using testing::_;
using testing::AtLeast;
using testing::Return;
using testing::SetArgumentPointee;
using testing::StrictMock;

class FilterTest : public testing::Test {
 protected:
  StrictMock<testing::MockILogView> mock_view_;
};

TEST_F(FilterTest, TestMessageMatching) {
  const int kNumRows = 3;
  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_, GetMessage(0))
      .WillRepeatedly(Return("I'm not included"));
  EXPECT_CALL(mock_view_, GetMessage(1))
      .WillRepeatedly(Return("I'm Included"));
  EXPECT_CALL(mock_view_, GetMessage(2))
      .WillRepeatedly(Return("I'm Included but also Excluded"));

  Filter include_nothing_contains(Filter::MESSAGE, Filter::CONTAINS,
                                  Filter::INCLUDE, L"NothingIncluded");
  for (int i = 0; i < kNumRows; i++) {
    EXPECT_FALSE(include_nothing_contains.Matches(&mock_view_, i));
  }

  Filter include_contains(Filter::MESSAGE, Filter::CONTAINS,
                          Filter::INCLUDE, L"included");
  for (int i = 0; i < kNumRows; i++) {
    EXPECT_TRUE(include_contains.Matches(&mock_view_, i));
  }

  Filter include_nothing_is(Filter::MESSAGE, Filter::IS,
                            Filter::INCLUDE, L"NothingIncluded");
  for (int i = 0; i < kNumRows; i++) {
    EXPECT_FALSE(include_nothing_is.Matches(&mock_view_, i));
  }

  Filter include_is(Filter::MESSAGE, Filter::IS,
                    Filter::INCLUDE, L"I'm included");
  for (int i = 0; i < kNumRows; i++) {
    if (i == 1)
      EXPECT_TRUE(include_is.Matches(&mock_view_, i));
    else
      EXPECT_FALSE(include_is.Matches(&mock_view_, i));
  }
}

TEST_F(FilterTest, TestPIDMatching) {
  const int kNumRows = 4;
  EXPECT_CALL(mock_view_, GetNumRows())
      .WillRepeatedly(Return(kNumRows));
  EXPECT_CALL(mock_view_, GetProcessId(0))
      .WillRepeatedly(Return(42));
  EXPECT_CALL(mock_view_, GetProcessId(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(mock_view_, GetProcessId(2))
      .WillRepeatedly(Return(999));
  EXPECT_CALL(mock_view_, GetProcessId(3))
      .WillRepeatedly(Return(4242));

  Filter include_nothing_contains(Filter::PROCESS_ID, Filter::CONTAINS,
                                  Filter::INCLUDE, L"3");
  for (int i = 0; i < kNumRows; i++) {
    EXPECT_FALSE(include_nothing_contains.Matches(&mock_view_, i));
  }

  Filter include_contains(Filter::PROCESS_ID, Filter::CONTAINS,
                                  Filter::INCLUDE, L"42");
  for (int i = 0; i < kNumRows; i++) {
    if (i == 0 || i == 3)
      EXPECT_TRUE(include_contains.Matches(&mock_view_, i));
    else
      EXPECT_FALSE(include_contains.Matches(&mock_view_, i));
  }

  Filter include_is(Filter::PROCESS_ID, Filter::IS,
                    Filter::INCLUDE, L"42");
  EXPECT_TRUE(include_is.Matches(&mock_view_, 0));
  for (int i = 1; i < kNumRows; i++) {
    EXPECT_FALSE(include_is.Matches(&mock_view_, i));
  }
}

TEST_F(FilterTest, TestSingleSerialization) {
  Filter filter_array[] = {
    Filter(Filter::MESSAGE, Filter::CONTAINS, Filter::INCLUDE, L""),
  };

  std::vector<Filter> filters;
  for (int i = 0; i < arraysize(filter_array); i++) {
    filters.push_back(filter_array[i]);
  }

  std::wstring serialized_filters(Filter::SerializeFilters(filters));

  std::vector<Filter> deserialized_filters = Filter::DeserializeFilters(
      serialized_filters);
  ASSERT_TRUE(filters.size() == deserialized_filters.size());
  for (size_t i = 0; i < filters.size(); i++) {
    EXPECT_TRUE(filters[i] == deserialized_filters[i]);
  }
}

TEST_F(FilterTest, TestMultipleSerialization) {
  Filter filter_array[] = {
    Filter(Filter::MESSAGE, Filter::CONTAINS, Filter::INCLUDE, L"Panic!!!"),
    Filter(Filter::PROCESS_ID, Filter::IS, Filter::EXCLUDE, L"42"),
    Filter(Filter::FILE, Filter::IS, Filter::EXCLUDE, L"w00t.cc"),
  };

  std::vector<Filter> filters;
  for (int i = 0; i < arraysize(filter_array); i++) {
    filters.push_back(filter_array[i]);
  }

  std::wstring serialized_filters(Filter::SerializeFilters(filters));
  EXPECT_STREQ(L"14|5|1|0|Panic!!!8|0|0|1|4213|3|0|1|w00t.cc",
               serialized_filters.c_str());

  std::vector<Filter> deserialized_filters = Filter::DeserializeFilters(
      serialized_filters);
  ASSERT_TRUE(filters.size() == deserialized_filters.size());
  for (size_t i = 0; i < filters.size(); i++) {
    EXPECT_TRUE(filters[i] == deserialized_filters[i]);
  }
}

TEST_F(FilterTest, TestEmptySerialization) {
  std::wstring serialized_filters(
      Filter::SerializeFilters(std::vector<Filter>()));
  EXPECT_STREQ(L"", serialized_filters.c_str());

  std::vector<Filter> deserialized_filters = Filter::DeserializeFilters(
      serialized_filters);
  ASSERT_TRUE(0 == deserialized_filters.size());
}
