// Copyright 2011 Google Inc.
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

#include "syzygy/instrument/instrumenter.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class InstrumenterTest : public testing::Test {
 public:
  void SetUp() {
    // Create a temporary file we can write a new image to.
    input_dll_path_ = testing::GetExeRelativePath(testing::kDllName);
    ASSERT_TRUE(file_util::CreateTemporaryFile(&output_dll_path_));
  }

  void TearDown() {
    file_util::Delete(output_dll_path_, false);
  }

 protected:
  FilePath input_dll_path_;
  FilePath output_dll_path_;
};

}  // namespace


TEST_F(InstrumenterTest, Instrument) {
  ASSERT_TRUE(Instrumenter::Instrument(input_dll_path_, output_dll_path_));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(output_dll_path_));
}
