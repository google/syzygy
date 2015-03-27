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

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/file_util.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/multiprocess_test.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "testing/multiprocess_func_list.h"

namespace kasko {

namespace {

const char kReadyEventSwitch[] = "ready-event";

// Signals an event named by kReadyEventSwitch, then blocks indefinitely.
MULTIPROCESS_TEST_MAIN(MinidumpTestBlockingProcess) {
  // Read the caller-supplied parameters.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  base::string16 ready_event_name =
      base::ASCIIToUTF16(cmd_line->GetSwitchValueASCII(kReadyEventSwitch));
  base::WaitableEvent ready_event(
      ::OpenEvent(EVENT_MODIFY_STATE, FALSE, ready_event_name.c_str()));
  ready_event.Signal();
  ::Sleep(INFINITE);
  return 0;
}

const char kCustomStreamContents[] = "hello world";
uint32_t kCustomStreamType = LastReservedStream + 2468;

void ValidateMinidump(IDebugClient4* debug_client,
                      IDebugControl* debug_control,
                      IDebugSymbols* debug_symbols) {
  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

}  // namespace

class MinidumpTest : public ::testing::Test {
 public:
  MinidumpTest() {}

  ~MinidumpTest() override {}

  // ::testing::Test implementation.
  virtual void SetUp() override { temp_dir_.CreateUniqueTempDir(); }

  void CallGenerateMinidump(const base::FilePath& dump_file_path,
                            MinidumpType minidump_type,
                            const std::vector<CustomStream>& custom_streams,
                            bool* result) {
    std::string ready_event_name =
        "minidump_test_ready_" + base::UintToString(base::GetCurrentProcId());

    base::WaitableEvent ready_event(::CreateEvent(
        NULL, FALSE, FALSE, base::ASCIIToUTF16(ready_event_name).c_str()));

    base::CommandLine child_command_line =
        base::GetMultiProcessTestChildBaseCommandLine();
    child_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                         "MinidumpTestBlockingProcess");
    child_command_line.AppendSwitchASCII(kReadyEventSwitch, ready_event_name);
    base::ProcessHandle child_process;
    ASSERT_TRUE(base::LaunchProcess(child_command_line, base::LaunchOptions(),
                                    &child_process));
    base::win::ScopedHandle scoped_child_process(child_process);
    ready_event.Wait();

    *result =
        kasko::GenerateMinidump(dump_file_path, base::GetProcId(child_process),
                                0, NULL, minidump_type, custom_streams);

    ASSERT_TRUE(base::KillProcess(child_process, 0, true));
  }

 protected:
  base::FilePath temp_dir() { return temp_dir_.path(); }

 private:
  base::ScopedTempDir temp_dir_;
  DISALLOW_COPY_AND_ASSIGN(MinidumpTest);
};

TEST_F(MinidumpTest, GenerateAndLoad) {
  // Generate a minidump for the current process.
  base::FilePath dump_file_path = temp_dir().Append(L"test.dump");
  std::vector<CustomStream> custom_streams;
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, SMALL_DUMP_TYPE,
                                               custom_streams, &result));
  ASSERT_TRUE(result);

  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST_F(MinidumpTest, CustomStream) {
  // Generate a minidump for the current process.
  base::FilePath dump_file_path = temp_dir().Append(L"test.dump");
  std::vector<CustomStream> custom_streams;
  CustomStream custom_stream = {kCustomStreamType,
                                kCustomStreamContents,
                                sizeof(kCustomStreamContents)};
  custom_streams.push_back(custom_stream);
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, SMALL_DUMP_TYPE,
                                               custom_streams, &result));
  ASSERT_TRUE(result);

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

TEST_F(MinidumpTest, MinidumpType) {
  // Generate a minidump for the current process.
  base::FilePath small_dump_file_path = temp_dir().Append(L"small.dump");
  base::FilePath larger_dump_file_path = temp_dir().Append(L"larger.dump");
  base::FilePath full_dump_file_path = temp_dir().Append(L"full.dump");
  std::vector<CustomStream> custom_streams;


  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(
      small_dump_file_path, SMALL_DUMP_TYPE, custom_streams, &result));
  ASSERT_TRUE(result);
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(
      larger_dump_file_path, LARGER_DUMP_TYPE, custom_streams, &result));
  ASSERT_TRUE(result);
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(
      full_dump_file_path, FULL_DUMP_TYPE, custom_streams, &result));
  ASSERT_TRUE(result);

  // Use the relative file sizes to infer that the correct minidump type was
  // respected.
  // Other approaches (testing the memory ranges included in the dump) were
  // rejected due to the difficulty of deterministically knowing what should and
  // shouldn't be included in the various dump types.
  int64 small_dump_size = 0;
  int64 larger_dump_size = 0;
  int64 full_dump_size = 0;

  ASSERT_TRUE(base::GetFileSize(small_dump_file_path, &small_dump_size));
  ASSERT_TRUE(base::GetFileSize(larger_dump_file_path, &larger_dump_size));
  ASSERT_TRUE(base::GetFileSize(full_dump_file_path, &full_dump_size));

  EXPECT_GT(full_dump_size, larger_dump_size);
  EXPECT_GT(larger_dump_size, small_dump_size);
}

TEST_F(MinidumpTest, OverwriteExistingFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir.path(), &dump_file_path));
  std::vector<CustomStream> custom_streams;

  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, SMALL_DUMP_TYPE,
                                               custom_streams, &result));
  ASSERT_TRUE(result);

  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST_F(MinidumpTest, NonexistantTargetDirectory) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  std::vector<CustomStream> custom_streams;
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(
      temp_dir.path().Append(L"Foobar").Append(L"HelloWorld"), SMALL_DUMP_TYPE,
      custom_streams, &result));
  ASSERT_FALSE(result);
}

}  // namespace kasko
