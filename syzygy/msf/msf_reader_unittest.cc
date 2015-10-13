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

#include "syzygy/msf/msf_reader.h"

#include "base/path_service.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/msf/msf_constants.h"
#include "syzygy/msf/unittest_util.h"

namespace msf {

TEST(MsfReaderTest, Read) {
  base::FilePath test_dll_msf =
      testing::GetSrcRelativePath(testing::kTestPdbFilePath);

  MsfReader reader;
  MsfFile msf_file;
  EXPECT_TRUE(reader.Read(test_dll_msf, &msf_file));
  EXPECT_EQ(msf_file.StreamCount(), 168u);
}

}  // namespace msf
