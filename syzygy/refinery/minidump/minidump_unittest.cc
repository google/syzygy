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

#include "syzygy/refinery/minidump/minidump.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"
#include "gtest/gtest.h"

namespace refinery {

namespace {

class MinidumpTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    dump_file_ = temp_dir_.path().Append(L"minidump.dmp");

    base::File dump_file;
    dump_file.Initialize(
        dump_file_, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    ASSERT_TRUE(dump_file.IsValid());

    ASSERT_TRUE(::MiniDumpWriteDump(base::GetCurrentProcessHandle(),
                                    base::GetCurrentProcId(),
                                    dump_file.GetPlatformFile(),
                                    MiniDumpNormal,
                                    nullptr,
                                    nullptr,
                                    nullptr));
  }

  const base::FilePath& dump_file() const { return dump_file_; }

 private:
  base::FilePath dump_file_;
  base::ScopedTempDir temp_dir_;
};

}  // namespace

TEST_F(MinidumpTest, Open) {
  Minidump minidump;

  ASSERT_TRUE(minidump.Open(dump_file()));
  ASSERT_LE(1U, minidump.directory().size());
}

TEST_F(MinidumpTest, FindNextStream) {
  Minidump minidump;

  ASSERT_TRUE(minidump.Open(dump_file()));

  Minidump::Stream sys_info =
      minidump.FindNextStream(nullptr, SystemInfoStream);
  ASSERT_TRUE(sys_info.IsValid());

  MINIDUMP_SYSTEM_INFO info = {};
  EXPECT_TRUE(sys_info.ReadElement(&info));

  Minidump::Stream invalid =
      minidump.FindNextStream(&sys_info, SystemInfoStream);
  EXPECT_FALSE(invalid.IsValid());
}

TEST_F(MinidumpTest, ReadThreadInfo) {
  Minidump minidump;

  ASSERT_TRUE(minidump.Open(dump_file()));

  Minidump::Stream thread_list =
      minidump.FindNextStream(nullptr, ThreadListStream);
  ASSERT_TRUE(thread_list.IsValid());

  ULONG32 num_threads = 0;
  ASSERT_TRUE(thread_list.ReadElement(&num_threads));

  for (size_t i = 0; i < num_threads; ++i) {
    MINIDUMP_THREAD thread = {};
    ASSERT_TRUE(thread_list.ReadElement(&thread));

    Minidump::Stream thread_memory =
        minidump.GetStreamFor(thread.Stack.Memory);
    EXPECT_TRUE(thread_memory.IsValid());

    Minidump::Stream thread_context =
        minidump.GetStreamFor(thread.ThreadContext);
    EXPECT_TRUE(thread_context.IsValid());

    CONTEXT ctx = {};
    EXPECT_TRUE(thread_context.ReadElement(&ctx));
  }
}

}  // namespace refinery
