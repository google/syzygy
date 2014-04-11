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

#include "syzygy/ar/ar_transform.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/ar/ar_reader.h"
#include "syzygy/ar/unittest_util.h"
#include "syzygy/core/unittest_util.h"

namespace ar {

namespace {

using testing::_;
using testing::Invoke;
using testing::Return;

// Test fixture.
class LenientArTransformTest : public testing::Test {
 public:
  LenientArTransformTest()
      : in_memory_callback_(base::Bind(
            &LenientArTransformTest::InMemoryCallback,
            base::Unretained(this))),
        on_disk_callback_(base::Bind(
            &LenientArTransformTest::OnDiskCallback,
            base::Unretained(this))),
        on_disk_adapter_(on_disk_callback_) {
  }

  virtual void SetUp() OVERRIDE {
    input_archive_ = testing::GetSrcRelativePath(testing::kArchiveFile);
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"ArTransformTest",
                                                  &temp_dir_));
    output_archive_ = temp_dir_.Append(L"output.lib");
  }

  virtual void TearDown() OVERRIDE {
    ASSERT_TRUE(file_util::Delete(temp_dir_, true));
  }

  MOCK_METHOD3(InMemoryCallback, bool(ParsedArFileHeader*,
                                      DataBuffer*,
                                      bool*));

  MOCK_METHOD4(OnDiskCallback, bool(const base::FilePath&,
                                    const base::FilePath&,
                                    ParsedArFileHeader*,
                                    bool*));

  bool InMemoryCallbackDeleteFile(ParsedArFileHeader* header,
                                  DataBuffer* contents,
                                  bool* remove) {
    *remove = true;
    return true;
  }

  bool OnDiskCallbackDeleteFile(const base::FilePath& input_path,
                                const base::FilePath& output_path,
                                ParsedArFileHeader* header,
                                bool* remove) {
    *remove = true;
    return true;
  }

  bool OnDiskCallbackCopyFile(const base::FilePath& input_path,
                              const base::FilePath& output_path,
                              ParsedArFileHeader* header,
                              bool* remove) {
    if (!file_util::CopyFileW(input_path, output_path))
      return false;
    return true;
  }

  base::FilePath input_archive_;
  base::FilePath output_archive_;
  base::FilePath temp_dir_;

  ArTransform::TransformFileCallback in_memory_callback_;
  OnDiskArTransformAdapter::TransformFileOnDiskCallback on_disk_callback_;
  OnDiskArTransformAdapter on_disk_adapter_;
};
typedef testing::StrictMock<LenientArTransformTest> ArTransformTest;

}  // namespace

TEST_F(ArTransformTest, TransformFailsBadInput) {
  base::FilePath bad_path(L"this_should_never_exist.lib");
  ArTransform tx;
  tx.set_input_archive(bad_path);
  tx.set_output_archive(output_archive_);
  tx.set_callback(in_memory_callback_);
  EXPECT_FALSE(tx.Transform());
}

TEST_F(ArTransformTest, TransformFailsInMemoryCallbackFails) {
  ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(in_memory_callback_);

  EXPECT_CALL(*this, InMemoryCallback(_, _, _))
      .Times(1).WillOnce(Return(false));

  EXPECT_FALSE(tx.Transform());
  EXPECT_FALSE(file_util::PathExists(output_archive_));
}

TEST_F(ArTransformTest, TransformIdentityInMemory) {
  ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(in_memory_callback_);

  EXPECT_CALL(*this, InMemoryCallback(_, _, _))
      .Times(testing::kArchiveFileCount).WillRepeatedly(Return(true));

  EXPECT_TRUE(tx.Transform());
  EXPECT_TRUE(file_util::PathExists(output_archive_));

  ArReader reader;
  EXPECT_TRUE(reader.Init(output_archive_));
  EXPECT_EQ(testing::kArchiveFileCount, reader.offsets().size());
}

TEST_F(ArTransformTest, TransformFailsOnDiskCallbackFails) {
    ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(on_disk_adapter_.outer_callback());

  EXPECT_CALL(*this, OnDiskCallback(_, _, _, _))
      .Times(1).WillRepeatedly(Return(true));

  EXPECT_FALSE(tx.Transform());
  EXPECT_FALSE(file_util::PathExists(output_archive_));
}

TEST_F(ArTransformTest, TransformIdentityOnDiskFailsNoOutputFile) {
    ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(on_disk_adapter_.outer_callback());

  EXPECT_CALL(*this, OnDiskCallback(_, _, _, _))
      .Times(1).WillOnce(Return(true));

  EXPECT_FALSE(tx.Transform());
  EXPECT_FALSE(file_util::PathExists(output_archive_));
}

TEST_F(ArTransformTest, TransformIdentityOnDisk) {
    ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(on_disk_adapter_.outer_callback());

  EXPECT_CALL(*this, OnDiskCallback(_, _, _, _))
      .Times(testing::kArchiveFileCount)
      .WillRepeatedly(Invoke(this, &ArTransformTest::OnDiskCallbackCopyFile));

  EXPECT_TRUE(tx.Transform());
  EXPECT_TRUE(file_util::PathExists(output_archive_));

  ArReader reader;
  EXPECT_TRUE(reader.Init(output_archive_));
  EXPECT_EQ(testing::kArchiveFileCount, reader.offsets().size());
}

TEST_F(ArTransformTest, TransformIdentityOnDiskEraseFile) {
    ArTransform tx;
  tx.set_input_archive(input_archive_);
  tx.set_output_archive(output_archive_);
  tx.set_callback(on_disk_adapter_.outer_callback());

  // Copy all of the files over except for the second one.
  EXPECT_CALL(*this, OnDiskCallback(_, _, _, _))
      .Times(testing::kArchiveFileCount)
      .WillOnce(Invoke(this, &ArTransformTest::OnDiskCallbackCopyFile))
      .WillOnce(Invoke(this, &ArTransformTest::OnDiskCallbackDeleteFile))
      .WillRepeatedly(Invoke(this, &ArTransformTest::OnDiskCallbackCopyFile));

  EXPECT_TRUE(tx.Transform());
  EXPECT_TRUE(file_util::PathExists(output_archive_));

  ArReader reader;
  EXPECT_TRUE(reader.Init(output_archive_));
  EXPECT_EQ(testing::kArchiveFileCount - 1, reader.offsets().size());
}

}  // namespace ar
