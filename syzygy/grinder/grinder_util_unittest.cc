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

#include "syzygy/grinder/grinder_util.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace grinder {

namespace {

const wchar_t kCoverageInstrumentedTestDll[] =
    L"coverage_instrumented_test_dll.dll";
const wchar_t kCoverageInstrumentedTestDllPdb[] =
    L"coverage_instrumented_test_dll.pdb";

}  // namespace

TEST(GrinderUtilTest, GetBasicBlockAddresses) {
  FilePath pdb_path = testing::GetExeTestDataRelativePath(
      kCoverageInstrumentedTestDllPdb);

  RelativeAddressVector bb_addresses;
  EXPECT_TRUE(GetBasicBlockAddresses(pdb_path, &bb_addresses));
  EXPECT_LT(0u, bb_addresses.size());
}

}  // namespace grinder
