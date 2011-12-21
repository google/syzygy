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

#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/instrumenter.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {

namespace {

class InstrumenterTest : public testing::PELibUnitTest {
  // Put your specializations here
};

}  // namespace

TEST_F(InstrumenterTest, Instrument) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath input_dll_path = testing::GetExeRelativePath(kDllName);
  FilePath input_pdb_path = testing::GetExeRelativePath(kDllPdbName);
  FilePath output_dll_path = temp_dir.Append(kDllName);
  FilePath output_pdb_path = temp_dir.Append(kDllPdbName);

  Instrumenter instrumenter;
  ASSERT_TRUE(instrumenter.Instrument(input_dll_path,
                                      input_pdb_path,
                                      output_dll_path,
                                      output_pdb_path));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));
}

}  // namespace instrument
