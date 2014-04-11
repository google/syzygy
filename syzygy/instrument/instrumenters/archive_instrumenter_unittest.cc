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

#include "syzygy/instrument/instrumenters/archive_instrumenter.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/ar/unittest_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/instrumenters/asan_instrumenter.h"
#include "syzygy/pe/unittest_util.h"

namespace instrument {
namespace instrumenters {

namespace {

// Some global state that is updated by IdentityInstrumenter.
// NOTE: Because of these this unittest is not thread safe! We could do this
//       with a complicate usage of gmock, but that's overkill for this
//       scenario.
size_t constructor_count = 0;
size_t parse_count = 0;
size_t instrument_count = 0;
std::set<base::FilePath> input_images;
std::set<base::FilePath> output_images;

// An identity instrumenter. Simply copies the input-image to the output-image.
class IdentityInstrumenter : public InstrumenterInterface {
 public:
  IdentityInstrumenter() {
    ++constructor_count;
  }

  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE {
    ++parse_count;
    input_image_ = command_line->GetSwitchValuePath("input-image");
    output_image_ = command_line->GetSwitchValuePath("output-image");
    input_images.insert(input_image_);
    output_images.insert(output_image_);
    return true;
  }

  virtual bool Instrument() OVERRIDE {
    ++instrument_count;
    file_util::CopyFile(input_image_, output_image_);
    return true;
  }

  base::FilePath input_image_;
  base::FilePath output_image_;
};

InstrumenterInterface* IdentityInstrumenterFactory() {
  return new IdentityInstrumenter();
}

InstrumenterInterface* AsanInstrumenterFactory() {
  return new AsanInstrumenter();
}

class ArchiveInstrumenterTest : public testing::PELibUnitTest {
 public:
  virtual void SetUp() OVERRIDE {
    testing::PELibUnitTest::SetUp();

    CreateTemporaryDir(&temp_dir_);
    test_dll_dll_ = testing::GetExeTestDataRelativePath(
        testing::kTestDllName);
    zlib_lib_ = testing::GetSrcRelativePath(testing::kArchiveFile);
    output_image_ = temp_dir_.Append(L"output.dat");

    command_line_.reset(new CommandLine(base::FilePath(L"instrumenter.exe")));
    command_line_->AppendSwitchPath("output-image", output_image_);

    // Reset function counts.
    constructor_count = 0;
    parse_count = 0;
    instrument_count = 0;
    input_images.clear();
    output_images.clear();
  }

  virtual void TearDown() OVERRIDE {
    testing::PELibUnitTest::TearDown();
  }

  base::FilePath temp_dir_;
  base::FilePath test_dll_dll_;
  base::FilePath zlib_lib_;
  base::FilePath output_image_;

  scoped_ptr<CommandLine> command_line_;
};

}  // namespace

TEST_F(ArchiveInstrumenterTest, PassthroughForNonArchive) {
  ArchiveInstrumenter inst(&IdentityInstrumenterFactory);
  command_line_->AppendSwitchPath("input-image", test_dll_dll_);

  EXPECT_TRUE(inst.ParseCommandLine(command_line_.get()));
  EXPECT_TRUE(inst.Instrument());
  EXPECT_EQ(1u, constructor_count);
  EXPECT_EQ(1u, parse_count);
  EXPECT_EQ(1u, instrument_count);
  EXPECT_EQ(1u, input_images.size());
  EXPECT_EQ(1u, output_images.size());
  EXPECT_EQ(test_dll_dll_, *input_images.begin());
  EXPECT_EQ(output_image_, *output_images.begin());
  EXPECT_TRUE(file_util::PathExists(output_image_));
}

TEST_F(ArchiveInstrumenterTest, IteratesOverArchiveFiles) {
  ArchiveInstrumenter inst(&IdentityInstrumenterFactory);
  command_line_->AppendSwitchPath("input-image", zlib_lib_);

  EXPECT_TRUE(inst.ParseCommandLine(command_line_.get()));
  EXPECT_TRUE(inst.Instrument());
  EXPECT_EQ(testing::kArchiveFileCount, constructor_count);
  EXPECT_EQ(testing::kArchiveFileCount, parse_count);
  EXPECT_EQ(testing::kArchiveFileCount, instrument_count);
  EXPECT_EQ(testing::kArchiveFileCount, input_images.size());
  EXPECT_EQ(testing::kArchiveFileCount, output_images.size());
  EXPECT_EQ(0u, input_images.count(zlib_lib_));
  EXPECT_EQ(0u, output_images.count(output_image_));
  EXPECT_TRUE(file_util::PathExists(output_image_));
}

TEST_F(ArchiveInstrumenterTest, AsanInstrumentArchive) {
  ArchiveInstrumenter inst(&AsanInstrumenterFactory);
  command_line_->AppendSwitchPath("input-image", zlib_lib_);

  EXPECT_TRUE(inst.ParseCommandLine(command_line_.get()));
  EXPECT_TRUE(inst.Instrument());
  EXPECT_TRUE(file_util::PathExists(output_image_));
}

}  // namespace instrumenters
}  // namespace instrument
