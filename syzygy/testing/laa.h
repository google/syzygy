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
//
// Contains utilities for early aborting tests that should only run in one
// memory model: Large Address Aware or otherwise.

#ifndef SYZYGY_TESTING_LAA_H_
#define SYZYGY_TESTING_LAA_H_

namespace testing {

// Returns the size of the memory model of the current process, in GB.
// Returns 2 (for non-LAA processes), or 4 (for LAA processes).
size_t GetAddressSpaceSize();

// Returns true if the test should be skipped because it only supports
// the given address space size.
bool ShouldSkipTest(size_t required_address_space_size);

// Macros to be used to early exit a test that should only run in a 2GB/4GB
// memory model. This is meant to be used as the first line in a test body,
// and/or in the SetUp and TearDown functions of a fixture.
#define TEST_ONLY_SUPPORTS_2G()     \
  if (::testing::ShouldSkipTest(2)) \
    return;
#define TEST_ONLY_SUPPORTS_4G()     \
  if (::testing::ShouldSkipTest(4)) \
    return;

// Macros to be used in declaring tests that only run in certain memory models.
#define TEST_2G(test_case_name, test_name)  \
    TEST(test_case_name, test_name ## _2G)
#define TEST_F_2G(test_case_name, test_name)  \
    TEST_F(test_case_name, test_name ## _2G)
#define TEST_4G(test_case_name, test_name)  \
    TEST(test_case_name, test_name ## _4G)
#define TEST_F_4G(test_case_name, test_name)  \
    TEST_F(test_case_name, test_name ## _4G)

}  // namespace testing

#endif  // SYZYGY_TESTING_LAA_H_
