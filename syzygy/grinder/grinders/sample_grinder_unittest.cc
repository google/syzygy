// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/grinder/grinders/sample_grinder.h"

#include "base/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/sampler/unittest_util.h"
#include "syzygy/trace/common/clock.h"
#include "syzygy/trace/common/unittest_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace grinder {
namespace grinders {

namespace {

const wchar_t kTestDllLabelTestFuncAsm[] =
    L"syzygy\\pe\\test_dll_label_test_func.asm";

// SampleGrinder with some internal details exposed for testing.
class TestSampleGrinder : public SampleGrinder {
 public:
  // Functions.
  using SampleGrinder::UpsampleModuleData;
  using SampleGrinder::IncrementModuleData;
  using SampleGrinder::IncrementHeatMapFromModuleData;
  using SampleGrinder::RollUpByName;

  // Members.
  using SampleGrinder::aggregation_level_;
  using SampleGrinder::image_path_;
  using SampleGrinder::parser_;
  using SampleGrinder::heat_map_;
  using SampleGrinder::name_heat_map_;
  using SampleGrinder::line_info_;
};

class SampleGrinderTest : public testing::PELibUnitTest {
 public:
  SampleGrinderTest()
      : cmd_line_(base::FilePath(L"sample_grinder.exe")),
        sample_data_(NULL) {
    trace::common::GetClockInfo(&clock_info_);
  }

  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();
    test_dll_path_ = testing::GetOutputRelativePath(testing::kTestDllName);
    ASSERT_TRUE(test_dll_pe_file_.Init(test_dll_path_));
    test_dll_pe_file_.GetSignature(&test_dll_pe_sig_);
  }

  void PrepareDummySampleDataBuffer(size_t bucket_count) {
    ASSERT_EQ(0u, buffer_.size());
    ASSERT_TRUE(sample_data_ == NULL);

    buffer_.resize(offsetof(TraceSampleData, buckets) +
                       sizeof(uint32) * bucket_count);
    sample_data_ = reinterpret_cast<TraceSampleData*>(buffer_.data());
  }

  void WriteDummySampleData() {
    ASSERT_FALSE(test_dll_path_.empty());
    ASSERT_TRUE(temp_dir_.empty());
    ASSERT_TRUE(trace_file_path_.empty());

    this->CreateTemporaryDir(&temp_dir_);

    trace_file_path_ = temp_dir_.AppendASCII("sample.bin");
    ASSERT_NO_FATAL_FAILURE(testing::WriteDummySamplerTraceFile(
        trace_file_path_));
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler) {
    ASSERT_TRUE(handler != NULL);
    ASSERT_TRUE(parser_.Init(handler));
    ASSERT_TRUE(parser_.OpenTraceFile(trace_file_path_));
  }

  void GrindSucceeds(SampleGrinder::AggregationLevel aggregation_level,
                     bool specify_image) {
    TestSampleGrinder g;

    if (specify_image)
      cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);

    cmd_line_.AppendSwitchASCII(
        SampleGrinder::kAggregationLevel,
        SampleGrinder::kAggregationLevelNames[aggregation_level]);
    ASSERT_TRUE(g.ParseCommandLine(&cmd_line_));

    ASSERT_NO_FATAL_FAILURE(WriteDummySampleData());
    ASSERT_NO_FATAL_FAILURE(InitParser(&g));
    g.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    ASSERT_TRUE(g.Grind());

    // 1000 samples at a rate of 0.01 samples/sec = 10 seconds of heat.
    const double expected_heat = 10.0;
    double total_heat = 0;

    // Check that the output has gone to the right intermediate representation
    // after grinding. We also check that there was a non-zero amount of
    // 'heat' distributed.
    if (aggregation_level == SampleGrinder::kBasicBlock) {
      ASSERT_FALSE(g.heat_map_.empty());
      ASSERT_TRUE(g.name_heat_map_.empty());
      ASSERT_TRUE(g.line_info_.source_lines().empty());

      TestSampleGrinder::HeatMap::const_iterator it =
          g.heat_map_.begin();
      for (; it != g.heat_map_.end(); ++it) {
        if (it->second.heat > 0)
          LOG(INFO) << ".";
        total_heat += it->second.heat;
      }

      EXPECT_DOUBLE_EQ(expected_heat, total_heat);
    } else if (aggregation_level == SampleGrinder::kCompiland ||
               aggregation_level == SampleGrinder::kFunction) {
      ASSERT_TRUE(g.heat_map_.empty());
      ASSERT_FALSE(g.name_heat_map_.empty());
      ASSERT_TRUE(g.line_info_.source_lines().empty());

      // Look through the NameHeatMap output.
      bool compiland_seen = false;
      bool function_seen = false;
      TestSampleGrinder::NameHeatMap::const_iterator it =
          g.name_heat_map_.begin();
      for (; it != g.name_heat_map_.end(); ++it) {
        base::FilePath path(UTF8ToWide(*it->first));
        if (path.BaseName().value() == L"test_dll_label_test_func.obj")
          compiland_seen = true;
        if (*it->first == "_LabelTestFunc")
          function_seen = true;
        if (it->second > 0)
          LOG(INFO) << ".";
        total_heat += it->second;
      }

      if (aggregation_level == SampleGrinder::kCompiland) {
        EXPECT_TRUE(compiland_seen);
        EXPECT_FALSE(function_seen);
      } else {
        EXPECT_FALSE(compiland_seen);
        EXPECT_TRUE(function_seen);
      }
    } else {
      ASSERT_EQ(SampleGrinder::kLine, aggregation_level);
      ASSERT_TRUE(g.heat_map_.empty());
      ASSERT_TRUE(g.name_heat_map_.empty());
      ASSERT_FALSE(g.line_info_.source_lines().empty());

      // Get the path to the source file where all of the heat should land.
      base::FilePath source_file_path =
          testing::GetSrcRelativePath(kTestDllLabelTestFuncAsm);
      std::string source_file = WideToUTF8(source_file_path.value());

      // All of the heat is in the first 4-byte bucket of the LabelTestFunc.
      // Thus, it will be spread evenly across the source ranges in those 4
      // bytes, with the lowest value scaled to 1. The scaling makes the visit
      // count the same as the encoded instruction size.
      typedef std::map<size_t, uint32> LineVisitCountMap;
      LineVisitCountMap expected, actual;
      expected[61] = 1;  // Label. Ends up being a 1 byte source range.
      expected[64] = 1;  // push ebp (1 byte).
      expected[65] = 2;  // mov ebp, esp (2 bytes).
      expected[66] = 1;  // push ecx (1 byte).

      uint32 min_visit_count = 0xFFFFFFFF;
      for (size_t i = 0; i < g.line_info_.source_lines().size(); ++i) {
        const LineInfo::SourceLine& line = g.line_info_.source_lines()[i];
        if (line.visit_count == 0)
          continue;

        if (line.visit_count < min_visit_count)
          min_visit_count = line.visit_count;

        EXPECT_EQ(StringToLowerASCII(source_file),
                  StringToLowerASCII(*line.source_file_name));
        actual[line.line_number] = line.visit_count;
      }
      EXPECT_EQ(1u, min_visit_count);

      EXPECT_THAT(expected, testing::ContainerEq(actual));

      // We can't say anything concrete about the total heat, as it has been
      // scaled such that the smallest non-zero value is a 1.
      total_heat = 10.0;
    }
    EXPECT_DOUBLE_EQ(10.0, total_heat);

    // Produce the output.
    base::FilePath csv_path = temp_dir_.Append(L"output.csv");
    file_util::ScopedFILE csv_file(file_util::OpenFile(csv_path, "wb"));
    ASSERT_TRUE(csv_file.get() != NULL);
    ASSERT_TRUE(g.OutputData(csv_file.get()));
    csv_file.reset();

    // Ensure output was produced.
    int64 file_size = 0;
    ASSERT_TRUE(file_util::GetFileSize(csv_path, &file_size));
    ASSERT_LT(0u, file_size);
  }

  base::FilePath test_dll_path_;
  pe::PEFile test_dll_pe_file_;
  pe::PEFile::Signature test_dll_pe_sig_;

  base::FilePath temp_dir_;
  base::FilePath trace_file_path_;

  CommandLine cmd_line_;
  trace::parser::Parser parser_;

  std::vector<uint8> buffer_;
  TraceSampleData* sample_data_;

  trace::common::ClockInfo clock_info_;
};

double BucketSum(const SampleGrinder::ModuleData& module_data) {
  double sum = 0;
  for (size_t i = 0; i < module_data.buckets.size(); ++i)
    sum += module_data.buckets[i];
  return sum;
}

}  // namespace

TEST_F(SampleGrinderTest, UpsampleModuleData) {
  SampleGrinder::ModuleData module_data;
  EXPECT_EQ(0u, module_data.buckets.size());
  EXPECT_EQ(0u, module_data.bucket_size);

  // UpsampleModuleData only cares about bucket_size and bucket_count, so no
  // need to worry about filling out a full TraceSampleData object.
  TraceSampleData sample_data = {};
  sample_data.bucket_count = 1000;
  sample_data.bucket_size = 8;
  TestSampleGrinder::UpsampleModuleData(&sample_data, &module_data);
  ASSERT_EQ(1000u, module_data.buckets.size());
  EXPECT_EQ(8u, module_data.bucket_size);
  module_data.buckets[0] = 2.0;
  EXPECT_DOUBLE_EQ(2.0, BucketSum(module_data));

  TestSampleGrinder::UpsampleModuleData(&sample_data, &module_data);
  ASSERT_EQ(1000u, module_data.buckets.size());
  EXPECT_EQ(8u, module_data.bucket_size);
  EXPECT_DOUBLE_EQ(2.0, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(2.0, BucketSum(module_data));

  sample_data.bucket_count = 500;
  sample_data.bucket_size = 16;
  TestSampleGrinder::UpsampleModuleData(&sample_data, &module_data);
  ASSERT_EQ(1000u, module_data.buckets.size());
  EXPECT_EQ(8u, module_data.bucket_size);
  EXPECT_DOUBLE_EQ(2.0, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(2.0, BucketSum(module_data));

  sample_data.bucket_count = 2000;
  sample_data.bucket_size = 4;
  TestSampleGrinder::UpsampleModuleData(&sample_data, &module_data);
  ASSERT_EQ(2000u, module_data.buckets.size());
  EXPECT_EQ(4u, module_data.bucket_size);
  EXPECT_DOUBLE_EQ(1.0, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(1.0, module_data.buckets[1]);
  EXPECT_DOUBLE_EQ(2.0, BucketSum(module_data));
}

TEST_F(SampleGrinderTest, IncrementModuleData) {
  ASSERT_NO_FATAL_FAILURE(PrepareDummySampleDataBuffer(5));
  ASSERT_TRUE(sample_data_ != NULL);

  // We make our sampling interval 1/10th of the clock rate, so that each
  // sample is worth 0.1 'seconds'.
  uint64 sampling_interval = clock_info_.tsc_info.frequency / 10;
  uint32 bucket_start = 0x00011000;

  sample_data_->module_base_addr = reinterpret_cast<ModuleAddr>(0x00100000);
  sample_data_->module_size = 0x00010000;
  sample_data_->module_checksum = 0xAAAAAAAA;
  sample_data_->module_time_date_stamp = 0xBBBBBBBB;
  sample_data_->bucket_size = 8;
  sample_data_->bucket_start = reinterpret_cast<ModuleAddr>(bucket_start);
  sample_data_->bucket_count = 5;
  sample_data_->sampling_start_time = 0;
  sample_data_->sampling_end_time = sampling_interval * 5;
  sample_data_->sampling_interval = sampling_interval;
  sample_data_->buckets[0] = 3;
  sample_data_->buckets[1] = 1;
  sample_data_->buckets[2] = 1;

  SampleGrinder::ModuleData module_data;
  module_data.bucket_start.set_value(bucket_start);
  TestSampleGrinder::UpsampleModuleData(sample_data_, &module_data);
  ASSERT_EQ(sample_data_->bucket_count, module_data.buckets.size());

  // If the bucket starts aren't aligned this should fail.
  module_data.bucket_start -= 4;
  EXPECT_FALSE(TestSampleGrinder::IncrementModuleData(
      clock_info_.tsc_info.frequency, sample_data_, &module_data));
  module_data.bucket_start += 4;

  // If the bucket lengths aren't consistent this should also fail.
  module_data.buckets.resize(sample_data_->bucket_count - 1);
  EXPECT_FALSE(TestSampleGrinder::IncrementModuleData(
      clock_info_.tsc_info.frequency, sample_data_, &module_data));
  module_data.buckets.resize(sample_data_->bucket_count);

  // If the bucket length and start are consistent, then this should pass.
  EXPECT_TRUE(TestSampleGrinder::IncrementModuleData(
      clock_info_.tsc_info.frequency, sample_data_, &module_data));
  EXPECT_EQ(8u, module_data.bucket_size);
  EXPECT_EQ(5u, module_data.buckets.size());
  EXPECT_DOUBLE_EQ(0.3, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(0.1, module_data.buckets[1]);
  EXPECT_DOUBLE_EQ(0.1, module_data.buckets[2]);
  EXPECT_DOUBLE_EQ(0.5, BucketSum(module_data));

  // Adding more of the same should work.
  EXPECT_TRUE(TestSampleGrinder::IncrementModuleData(
      clock_info_.tsc_info.frequency, sample_data_, &module_data));
  EXPECT_EQ(8u, module_data.bucket_size);
  EXPECT_EQ(5u, module_data.buckets.size());
  EXPECT_DOUBLE_EQ(0.6, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(0.2, module_data.buckets[1]);
  EXPECT_DOUBLE_EQ(0.2, module_data.buckets[2]);
  EXPECT_DOUBLE_EQ(1.0, BucketSum(module_data));

  // Adding larger buckets should see the values split across the finer
  // resolution aggregated buckets.
  sample_data_->bucket_count = 3;
  sample_data_->bucket_size = 16;
  sample_data_->buckets[0] = 2;
  sample_data_->buckets[1] = 0;
  sample_data_->buckets[2] = 0;
  EXPECT_TRUE(TestSampleGrinder::IncrementModuleData(
      clock_info_.tsc_info.frequency, sample_data_, &module_data));
  EXPECT_EQ(8u, module_data.bucket_size);
  EXPECT_EQ(5u, module_data.buckets.size());
  EXPECT_DOUBLE_EQ(0.7, module_data.buckets[0]);
  EXPECT_DOUBLE_EQ(0.3, module_data.buckets[1]);
  EXPECT_DOUBLE_EQ(0.2, module_data.buckets[2]);
  EXPECT_DOUBLE_EQ(1.2, BucketSum(module_data));
}

TEST_F(SampleGrinderTest, IncrementHeatMapFromModuleData) {
  // Make 9 buckets, each with 1 second of samples in them.
  SampleGrinder::ModuleData module_data;
  module_data.bucket_size = 4;
  module_data.buckets.resize(9, 1.0);

  // RVA    : 0     4     8     12    16    20    24    28    32    36
  // Buckets: |--0--|--1--|--2--|--3--|--4--|--5--|--6--|--7--|--8--|
  // Ranges : |--A--|B|       |C| |D| |E |F |  |--G--|  |H| |I|
  // A perfectly spans a bucket.
  // B aligns with the left edge of a bucket, but claims all of it.
  // C aligns with the right edge of a bucket, but claims all of it.
  // D is in the middle of a bucket and claims all of it.
  // E and F share a bucket, covering all of it.
  // G spans 2 buckets.
  // H and I share a bucket, but don't cover it entirely.

  typedef SampleGrinder::BasicBlockData BasicBlockData;
  typedef SampleGrinder::HeatMap HeatMap;
  typedef SampleGrinder::HeatMap::AddressSpace::Range Range;
  typedef SampleGrinder::HeatMap::AddressSpace::Range::Address RVA;

  HeatMap heat_map;
  const BasicBlockData kData = {};
  ASSERT_TRUE(heat_map.Insert(Range(RVA(0), 4), kData));  // A.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(4), 2), kData));  // B.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(10), 2), kData));  // C.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(13), 2), kData));  // D.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(16), 2), kData));  // E.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(18), 2), kData));  // F.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(22), 4), kData));  // G.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(28), 1), kData));  // H.
  ASSERT_TRUE(heat_map.Insert(Range(RVA(31), 1), kData));  // I.

  double total_samples = 0;
  double orphaned_samples = TestSampleGrinder::IncrementHeatMapFromModuleData(
      module_data, &heat_map, &total_samples);
  EXPECT_DOUBLE_EQ(1.0, orphaned_samples);
  EXPECT_DOUBLE_EQ(9.0, total_samples);

  // We expect the heat to have been distributed to the ranges in the following
  // quantities.
  const double kHeat[] = { /* A */ 1.0, /* B */ 1.0, /* C */ 1.0,
                           /* D */ 1.0, /* E */ 0.5, /* F */ 0.5,
                           /* G */ 2.0, /* H */ 0.5, /* I */ 0.5 };
  ASSERT_EQ(arraysize(kHeat), heat_map.size());
  HeatMap::const_iterator it = heat_map.begin();
  for (size_t i = 0; it != heat_map.end(); ++it, ++i)
    EXPECT_DOUBLE_EQ(kHeat[i], it->second.heat);
}

TEST_F(SampleGrinderTest, RollUpByName) {
  const std::string kFoo = "foo";
  const std::string kBar = "bar";

  typedef TestSampleGrinder::HeatMap::AddressSpace::Range Range;
  typedef TestSampleGrinder::HeatMap::AddressSpace::Range::Address RVA;

  // Create a very simple heat map.
  TestSampleGrinder::HeatMap heat_map;
  TestSampleGrinder::BasicBlockData bbd0 = { &kFoo, &kBar, 1.0 };
  TestSampleGrinder::BasicBlockData bbd1 = { &kBar, &kFoo, 2.0 };
  ASSERT_TRUE(heat_map.Insert(Range(RVA(0), 4), bbd0));
  ASSERT_TRUE(heat_map.Insert(Range(RVA(4), 4), bbd1));

  TestSampleGrinder::NameHeatMap nhm;
  TestSampleGrinder::NameHeatMap expected_nhm;

  expected_nhm[&kFoo] = 2.0;
  expected_nhm[&kBar] = 1.0;
  TestSampleGrinder::RollUpByName(SampleGrinder::kFunction, heat_map, &nhm);
  EXPECT_THAT(nhm, testing::ContainerEq(expected_nhm));

  nhm.clear();
  expected_nhm[&kFoo] = 1.0;
  expected_nhm[&kBar] = 2.0;
  TestSampleGrinder::RollUpByName(SampleGrinder::kCompiland, heat_map, &nhm);
  EXPECT_THAT(nhm, testing::ContainerEq(expected_nhm));
}

TEST_F(SampleGrinderTest, ParseEmptyCommandLineFails) {
  TestSampleGrinder g;
  EXPECT_FALSE(g.ParseCommandLine(&cmd_line_));
}

TEST_F(SampleGrinderTest, ParseMinimalCommandLineSucceeds) {
  TestSampleGrinder g;
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
  EXPECT_EQ(test_dll_path_, g.image_path_);
  EXPECT_EQ(SampleGrinder::kBasicBlock, g.aggregation_level_);
}

TEST_F(SampleGrinderTest, ParseCommandLineAggregationLevel) {
  // Test command line without specifying '--image'.

  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "basic-block");
  {
    TestSampleGrinder g;
    EXPECT_FALSE(g.ParseCommandLine(&cmd_line_));
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "function");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_TRUE(g.image_path_.empty());
    EXPECT_EQ(SampleGrinder::kFunction, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "compiland");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_TRUE(g.image_path_.empty());
    EXPECT_EQ(SampleGrinder::kCompiland, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "line");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_TRUE(g.image_path_.empty());
    EXPECT_EQ(SampleGrinder::kLine, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "foobar");
  {
    TestSampleGrinder g;
    EXPECT_FALSE(g.ParseCommandLine(&cmd_line_));
  }

  // Test command line when specifying '--image'.

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "basic-block");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_EQ(test_dll_path_, g.image_path_);
    EXPECT_EQ(SampleGrinder::kBasicBlock, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "function");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_EQ(test_dll_path_, g.image_path_);
    EXPECT_EQ(SampleGrinder::kFunction, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "line");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_EQ(test_dll_path_, g.image_path_);
    EXPECT_EQ(SampleGrinder::kLine, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "compiland");
  {
    TestSampleGrinder g;
    EXPECT_TRUE(g.ParseCommandLine(&cmd_line_));
    EXPECT_EQ(test_dll_path_, g.image_path_);
    EXPECT_EQ(SampleGrinder::kCompiland, g.aggregation_level_);
  }

  cmd_line_.Init(0, NULL);
  cmd_line_.AppendSwitchPath(SampleGrinder::kImage, test_dll_path_);
  cmd_line_.AppendSwitchASCII(SampleGrinder::kAggregationLevel, "foobar");
  {
    TestSampleGrinder g;
    EXPECT_FALSE(g.ParseCommandLine(&cmd_line_));
  }
}

TEST_F(SampleGrinderTest, SetParserSucceeds) {
  TestSampleGrinder g;
  EXPECT_TRUE(g.parser_ == NULL);

  g.SetParser(&parser_);
  EXPECT_EQ(&parser_, g.parser_);
}

TEST_F(SampleGrinderTest, GrindBasicBlock) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kBasicBlock, true));
}

TEST_F(SampleGrinderTest, GrindFunction) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kFunction, true));
}

TEST_F(SampleGrinderTest, GrindFunctionNoImageSpecified) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kFunction, false));
}

TEST_F(SampleGrinderTest, GrindCompiland) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kCompiland, true));
}

TEST_F(SampleGrinderTest, GrindCompilandNoImageSpecified) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kCompiland, false));
}

TEST_F(SampleGrinderTest, GrindLine) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kLine, true));
}

TEST_F(SampleGrinderTest, GrindLineNoImageSpecified) {
  TestSampleGrinder g;
  ASSERT_NO_FATAL_FAILURE(GrindSucceeds(SampleGrinder::kLine, false));
}

}  // namespace grinders
}  // namespace grinder
