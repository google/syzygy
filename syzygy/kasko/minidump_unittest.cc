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

#include "syzygy/kasko/minidump.h"

#include <Windows.h>  // NOLINT
#include <Dbgeng.h>
#include <DbgHelp.h>

#include <cstring>
#include <vector>

#include "base/bind.h"
#include "base/file_util.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"

namespace kasko {

namespace {

const char kCustomStreamContents[] = "hello world";
uint32_t kCustomStreamType = LastReservedStream + 2468;

void ValidateMinidump(IDebugClient4* debug_client,
                      IDebugControl* debug_control,
                      IDebugSymbols* debug_symbols) {
  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

}  // namespace

TEST(MinidumpTest, GenerateAndLoad) {
  // Generate a minidump for the current process.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path = temp_dir.path().Append(L"test.dump");
  std::vector<CustomStream> custom_streams;
  ASSERT_TRUE(kasko::GenerateMinidump(dump_file_path, ::GetCurrentProcessId(),
                                      0, NULL, custom_streams));

  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST(MinidumpTest, CustomStream) {
  // Generate a minidump for the current process.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path = temp_dir.path().Append(L"test.dump");
  std::vector<CustomStream> custom_streams;
  CustomStream custom_stream = {kCustomStreamType,
                                kCustomStreamContents,
                                sizeof(kCustomStreamContents)};
  custom_streams.push_back(custom_stream);
  ASSERT_TRUE(kasko::GenerateMinidump(dump_file_path, ::GetCurrentProcessId(),
                                      0, NULL, custom_streams));

  // Open the minidump file.
  base::MemoryMappedFile memory_mapped_file;
  ASSERT_TRUE(memory_mapped_file.Initialize(dump_file_path));

  // Access the custom stream.
  MINIDUMP_DIRECTORY* dir = nullptr;
  void* stream = nullptr;
  ULONG stream_length = 0;
  ASSERT_TRUE(::MiniDumpReadDumpStream(
      const_cast<uint8*>(memory_mapped_file.data()), kCustomStreamType, &dir,
      &stream, &stream_length));

  // Assert that the custom stream is what we expected.
  ASSERT_EQ(sizeof(kCustomStreamContents), stream_length);
  ASSERT_EQ(0, memcmp(stream, kCustomStreamContents, stream_length));
}

TEST(MinidumpTest, OverwriteExistingFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir.path(), &dump_file_path));
  std::vector<CustomStream> custom_streams;
  ASSERT_TRUE(kasko::GenerateMinidump(dump_file_path, ::GetCurrentProcessId(),
                                      0, NULL, custom_streams));
  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST(MinidumpTest, NonexistantTargetDirectory) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  std::vector<CustomStream> custom_streams;
  ASSERT_FALSE(kasko::GenerateMinidump(
      temp_dir.path().Append(L"Foobar").Append(L"HelloWorld"),
      ::GetCurrentProcessId(), 0, NULL, custom_streams));
}

}  // namespace kasko
