// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/common/asan_parameters.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace common {

TEST(AsanParametersTest, FlatAsanParametersConstructorNoStackIds) {
  InflatedAsanParameters iparams;
  SetDefaultAsanParameters(&iparams);
  FlatAsanParameters fparams(iparams);
  EXPECT_EQ(sizeof(AsanParameters), fparams.data().size());
  EXPECT_EQ(0, ::memcmp(&iparams, &fparams.params(), sizeof(AsanParameters)));
}

TEST(AsanParametersTest, FlatAsanParametersConstructorWithStackIds) {
  InflatedAsanParameters iparams;
  SetDefaultAsanParameters(&iparams);
  iparams.ignored_stack_ids_set.insert(0xCAFEBABE);

  FlatAsanParameters fparams(iparams);
  EXPECT_EQ(sizeof(AsanParameters) + 2 * sizeof(AsanStackId),
            fparams.data().size());

  // Patch up the things that will be different between the two structs.
  iparams.size = fparams.data().size();
  static_cast<AsanParameters*>(&iparams)->ignored_stack_ids =
      const_cast<AsanStackId*>(reinterpret_cast<const AsanStackId*>(
          fparams.data().data() + sizeof(AsanParameters)));
  const AsanParameters* aparams = &fparams.params();

  // Now compare the rest of their POD content.
  EXPECT_EQ(0, ::memcmp(&iparams, aparams, sizeof(AsanParameters)));

  // Finally, confirm that the stack IDs have been properly serialized.
  EXPECT_EQ(0xCAFEBABE, fparams->ignored_stack_ids[0]);
  EXPECT_EQ(NULL, fparams->ignored_stack_ids[1]);
}

TEST(AsanParametersTest, SetDefaultAsanParameters) {
  AsanParameters aparams = {};
  SetDefaultAsanParameters(&aparams);

  EXPECT_EQ(sizeof(AsanParameters), aparams.size);
  EXPECT_EQ(kAsanParametersVersion, aparams.version);
  EXPECT_EQ(kDefaultQuarantineSize, aparams.quarantine_size);
  EXPECT_EQ(kDefaultReportingPeriod, aparams.reporting_period);
  EXPECT_EQ(kDefaultBottomFramesToSkip, aparams.bottom_frames_to_skip);
  EXPECT_EQ(kDefaultMaxNumFrames, aparams.max_num_frames);
  EXPECT_EQ(kDefaultTrailerPaddingSize, aparams.trailer_padding_size);
  EXPECT_EQ(NULL, aparams.ignored_stack_ids);
  EXPECT_EQ(kDefaultQuarantineBlockSize, aparams.quarantine_block_size);
  EXPECT_EQ(kDefaultMiniDumpOnFailure,
            static_cast<bool>(aparams.minidump_on_failure));
  EXPECT_EQ(kDefaultExitOnFailure,
            static_cast<bool>(aparams.exit_on_failure));
  EXPECT_EQ(kDefaultCheckHeapOnFailure,
            static_cast<bool>(aparams.check_heap_on_failure));
  EXPECT_EQ(kDefaultLogAsText,
            static_cast<bool>(aparams.log_as_text));
  EXPECT_EQ(0u, aparams.reserved1);
  EXPECT_EQ(kDefaultAllocationGuardRate, aparams.allocation_guard_rate);
}

TEST(AsanParametersTest, InflateAsanParametersStackIdsPastEnd) {
  AsanParameters aparams = {};
  SetDefaultAsanParameters(&aparams);

  aparams.ignored_stack_ids = reinterpret_cast<AsanStackId*>(
      &aparams + 2);

  InflatedAsanParameters iparams;
  EXPECT_FALSE(InflateAsanParameters(&aparams, &iparams));
}

TEST(AsanParametersTest, InflateAsanParametersStackIdsBeforeBeginning) {
  AsanParameters aparams = {};
  SetDefaultAsanParameters(&aparams);

  aparams.ignored_stack_ids = reinterpret_cast<AsanStackId*>(
      &aparams - 1);

  InflatedAsanParameters iparams;
  EXPECT_FALSE(InflateAsanParameters(&aparams, &iparams));
}

TEST(AsanParametersTest, InflateAsanParametersStackIdsOverlapParams) {
  AsanParameters aparams = {};
  SetDefaultAsanParameters(&aparams);

  aparams.ignored_stack_ids = reinterpret_cast<AsanStackId*>(
      &aparams) + 2;

  InflatedAsanParameters iparams;
  EXPECT_FALSE(InflateAsanParameters(&aparams, &iparams));
}

TEST(AsanParametersTest, InflateAsanParametersStackIdsNoNull) {
  uint8 data[sizeof(AsanParameters) + sizeof(AsanStackId)] = { 0 };
  AsanParameters* aparams = reinterpret_cast<AsanParameters*>(data);
  SetDefaultAsanParameters(aparams);
  aparams->ignored_stack_ids = reinterpret_cast<AsanStackId*>(
      data + sizeof(AsanParameters));

  aparams->size = sizeof(data);
  aparams->ignored_stack_ids[0] = 0xDEADBEEF;

  InflatedAsanParameters iparams;
  EXPECT_FALSE(InflateAsanParameters(aparams, &iparams));
}

TEST(AsanParametersTest, InflateAsanParametersStackIds) {
  uint8 data[sizeof(AsanParameters) + 2 * sizeof(AsanStackId)] = { 0 };
  AsanParameters* aparams = reinterpret_cast<AsanParameters*>(data);
  SetDefaultAsanParameters(aparams);
  aparams->ignored_stack_ids = reinterpret_cast<AsanStackId*>(
      data + sizeof(AsanParameters));

  aparams->size = sizeof(data);
  aparams->ignored_stack_ids[0] = 0xDEADBEEF;
  aparams->ignored_stack_ids[1] = NULL;

  InflatedAsanParameters iparams;
  EXPECT_TRUE(InflateAsanParameters(aparams, &iparams));

  // We normalize the few fields we expect to differ, and the rest should be
  // the same.
  aparams->size = sizeof(AsanParameters);
  aparams->ignored_stack_ids = NULL;
  EXPECT_EQ(0, ::memcmp(aparams, &iparams, sizeof(AsanParameters)));

  // The ignored stack id should have been parsed.
  EXPECT_EQ(1u, iparams.ignored_stack_ids_set.size());
  EXPECT_EQ(1u, iparams.ignored_stack_ids_set.count(0xDEADBEEF));
}

TEST(AsanParametersTest, InflateAsanParametersNoStackIds) {
  AsanParameters aparams = {};
  SetDefaultAsanParameters(&aparams);

  InflatedAsanParameters iparams;
  EXPECT_TRUE(InflateAsanParameters(&aparams, &iparams));

  EXPECT_EQ(0, ::memcmp(&aparams, &iparams, sizeof(AsanParameters)));
}

TEST(AsanParametersTest, ParseAsanParametersSizeNotANumber) {
  static const wchar_t kParams[] = L"--quarantine_size=foo";
  InflatedAsanParameters iparams;
  EXPECT_FALSE(ParseAsanParameters(kParams, &iparams));
}

TEST(AsanParametersTest, ParseAsanParametersNegativeSize) {
  static const wchar_t kParams[] = L"--quarantine_size=-45";
  InflatedAsanParameters iparams;
  EXPECT_FALSE(ParseAsanParameters(kParams, &iparams));
}

TEST(AsanParametersTest, ParseAsanParametersFloatingPointSize) {
  static const wchar_t kParams[] = L"--quarantine_size=4.5";
  InflatedAsanParameters iparams;
  EXPECT_FALSE(ParseAsanParameters(kParams, &iparams));
}

TEST(AsanParametersTest, ParseAsanParametersInvalidStackId) {
  static const wchar_t kParams[] = L"--ignored_stack_ids=foobaz";
  InflatedAsanParameters iparams;
  EXPECT_FALSE(ParseAsanParameters(kParams, &iparams));
}

TEST(AsanParametersTest, ParseAsanParametersMinimal) {
  static const wchar_t kParams[] = L"";

  InflatedAsanParameters iparams;
  SetDefaultAsanParameters(&iparams);
  EXPECT_TRUE(ParseAsanParameters(kParams, &iparams));

  EXPECT_EQ(sizeof(AsanParameters), iparams.size);
  EXPECT_EQ(kAsanParametersVersion, iparams.version);
  EXPECT_EQ(kDefaultQuarantineSize, iparams.quarantine_size);
  EXPECT_EQ(kDefaultReportingPeriod, iparams.reporting_period);
  EXPECT_EQ(kDefaultBottomFramesToSkip, iparams.bottom_frames_to_skip);
  EXPECT_EQ(kDefaultMaxNumFrames, iparams.max_num_frames);
  EXPECT_EQ(kDefaultTrailerPaddingSize, iparams.trailer_padding_size);
  EXPECT_EQ(kDefaultQuarantineBlockSize, iparams.quarantine_block_size);
  EXPECT_EQ(kDefaultMiniDumpOnFailure,
            static_cast<bool>(iparams.minidump_on_failure));
  EXPECT_EQ(kDefaultExitOnFailure,
            static_cast<bool>(iparams.exit_on_failure));
  EXPECT_EQ(kDefaultCheckHeapOnFailure,
            static_cast<bool>(iparams.check_heap_on_failure));
  EXPECT_EQ(kDefaultLogAsText,
            static_cast<bool>(iparams.log_as_text));
  EXPECT_EQ(0u, iparams.reserved1);
  EXPECT_TRUE(iparams.ignored_stack_ids_set.empty());
}

TEST(AsanParametersTest, ParseAsanParametersMaximal) {
  static const wchar_t kParams[] =
      L"--quarantine_size=1024 "
      L"--quarantine_block_size=256 "
      L"--trailer_padding_size=100 "
      L"--compression_reporting_period=324 "
      L"--bottom_frames_to_skip=5 "
      L"--max_num_frames=27 "
      L"--ignored_stack_ids=0X1;0xDEADBEEF;0xBAADF00D;CAFEBABE "
      L"--exit_on_failure "
      L"--no_check_heap_on_failure "
      L"--minidump_on_failure "
      L"--no_log_as_text "
      L"--allocation_guard_rate=0.6 "
      L"--ignored_as_it_doesnt_exist";

  InflatedAsanParameters iparams;
  SetDefaultAsanParameters(&iparams);
  EXPECT_TRUE(ParseAsanParameters(kParams, &iparams));

  EXPECT_EQ(sizeof(AsanParameters), iparams.size);
  EXPECT_EQ(kAsanParametersVersion, iparams.version);
  EXPECT_EQ(1024, iparams.quarantine_size);
  EXPECT_EQ(324, iparams.reporting_period);
  EXPECT_EQ(5, iparams.bottom_frames_to_skip);
  EXPECT_EQ(27, iparams.max_num_frames);
  EXPECT_EQ(100, iparams.trailer_padding_size);
  EXPECT_EQ(256, iparams.quarantine_block_size);
  EXPECT_EQ(true, static_cast<bool>(iparams.minidump_on_failure));
  EXPECT_EQ(true, static_cast<bool>(iparams.exit_on_failure));
  EXPECT_EQ(false, static_cast<bool>(iparams.check_heap_on_failure));
  EXPECT_EQ(false, static_cast<bool>(iparams.log_as_text));
  EXPECT_EQ(0u, iparams.reserved1);
  EXPECT_EQ(0.6f, iparams.allocation_guard_rate);
  EXPECT_THAT(iparams.ignored_stack_ids_set,
              testing::ElementsAre(0x1, 0xBAADF00D, 0xCAFEBABE, 0xDEADBEEF));
}

}  // namespace common
