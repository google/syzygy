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

#include "syzygy/kasko/testing/safe_pipe_reader.h"

#include "base/test/test_timeouts.h"
#include "gtest/gtest.h"

namespace kasko {
namespace testing {

TEST(SafePipeReader, BasicTest) {
  SafePipeReader pipe_reader;
  ASSERT_TRUE(pipe_reader.IsValid());
  int data = 73;
  DWORD written = 0;
  ASSERT_TRUE(::WriteFile(pipe_reader.write_handle(), &data, sizeof(data),
                          &written, NULL));
  ASSERT_EQ(sizeof(data), written);
  int read_buffer = 0;
  ASSERT_TRUE(pipe_reader.ReadData(TestTimeouts::tiny_timeout(),
                                   sizeof(read_buffer), &read_buffer));
  ASSERT_EQ(data, read_buffer);
}

TEST(SafePipeReader, Timeout) {
  SafePipeReader pipe_reader;
  ASSERT_TRUE(pipe_reader.IsValid());
  int read_buffer = 0;
  ASSERT_FALSE(pipe_reader.ReadData(TestTimeouts::tiny_timeout(),
                                    sizeof(read_buffer), &read_buffer));
}

TEST(SafePipeReader, IncompleteData) {
  SafePipeReader pipe_reader;
  ASSERT_TRUE(pipe_reader.IsValid());

  int data = 73;
  DWORD written = 0;
  ASSERT_TRUE(::WriteFile(pipe_reader.write_handle(), &data, sizeof(data) - 1,
                          &written, NULL));
  ASSERT_EQ(sizeof(data) - 1, written);

  int read_buffer = 0;
  ASSERT_FALSE(pipe_reader.ReadData(TestTimeouts::tiny_timeout(),
                                    sizeof(read_buffer), &read_buffer));
}

}  // namespace testing
}  // namespace kasko
