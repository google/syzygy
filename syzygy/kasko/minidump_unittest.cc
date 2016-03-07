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
#include <Psapi.h>

#include <cstring>
#include <vector>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/memory_mapped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/kill.h"
#include "base/process/launch.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/multiprocess_test.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/loader_lock.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/testing/minidump_unittest_helpers.h"
#include "syzygy/kasko/testing/safe_pipe_reader.h"
#include "syzygy/minidump/minidump.h"
#include "testing/multiprocess_func_list.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace kasko {

namespace {

const char kPipeHandleSwitch[] = "pipe-handle";

// Signals an event named by kReadyEventSwitch, then blocks indefinitely.
MULTIPROCESS_TEST_MAIN(MinidumpTestBlockingProcess) {
  // Read the caller-supplied parameters.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  std::string pipe_handle_string =
      cmd_line->GetSwitchValueASCII(kPipeHandleSwitch);
  unsigned handle_value = 0;
  CHECK(base::StringToUint(pipe_handle_string, &handle_value));
  base::win::ScopedHandle pipe(reinterpret_cast<HANDLE>(handle_value));
  DWORD written = 0;
  uint32_t image_base = reinterpret_cast<uint32_t>(&__ImageBase);
  PCHECK(WriteFile(pipe.Get(), &image_base, sizeof(image_base), &written,
                   nullptr));
  CHECK_EQ(sizeof(void*), written);
  pipe.Close();
  ::Sleep(INFINITE);
  return 0;
}

const char kGlobalString[] = "a global string";

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
  void SetUp() override { temp_dir_.CreateUniqueTempDir(); }

  // Launches a child process, waits until it has loaded, and then invokes
  // GenerateMinidump for the child.
  // The contents of |request().memory_ranges| must be within the current image
  // (kasko_unittests.exe). They will be adjusted so as to read the same offset
  // (from the image base) in the child process.
  void CallGenerateMinidump(const base::FilePath& dump_file_path,
                            bool* result) {
    testing::SafePipeReader pipe_reader;
    base::CommandLine child_command_line =
        base::GetMultiProcessTestChildBaseCommandLine();
    child_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                         "MinidumpTestBlockingProcess");
    child_command_line.AppendSwitchASCII(
        kPipeHandleSwitch, base::UintToString(reinterpret_cast<unsigned>(
                               pipe_reader.write_handle())));
    base::LaunchOptions options;
    options.inherit_handles = true;
    base::Process child_process =
        base::LaunchProcess(child_command_line, options);
    ASSERT_TRUE(child_process.IsValid());
    uint32_t child_image_base = 0;
    ASSERT_TRUE(pipe_reader.ReadData(base::TimeDelta::FromSeconds(15),
                                     sizeof(child_image_base),
                                     &child_image_base));

    MinidumpRequest adjusted_request = request_;
    for (auto& range : request_.user_selected_memory_ranges) {
      range = range.Offset(child_image_base -
                           reinterpret_cast<uint32_t>(&__ImageBase));
    }
    *result = kasko::GenerateMinidump(dump_file_path, child_process.Handle(), 0,
                                      adjusted_request);

    ASSERT_TRUE(child_process.Terminate(0, true));
  }

 protected:
  base::FilePath temp_dir() { return temp_dir_.path(); }
  MinidumpRequest& request() { return request_; }

 private:
  MinidumpRequest request_;
  base::ScopedTempDir temp_dir_;
  DISALLOW_COPY_AND_ASSIGN(MinidumpTest);
};

TEST_F(MinidumpTest, GenerateAndLoad) {
  // Generate a minidump for the current process.
  base::FilePath dump_file_path = temp_dir().Append(L"test.dump");
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, &result));
  ASSERT_TRUE(result);

  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST_F(MinidumpTest, CustomStream) {
  // Generate a minidump for the current process.
  base::FilePath dump_file_path = temp_dir().Append(L"test.dump");
  MinidumpRequest::CustomStream custom_stream = {
      kCustomStreamType, kCustomStreamContents, sizeof(kCustomStreamContents)};
  request().custom_streams.push_back(custom_stream);
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, &result));
  ASSERT_TRUE(result);

  // Open the minidump file.
  base::MemoryMappedFile memory_mapped_file;
  ASSERT_TRUE(memory_mapped_file.Initialize(dump_file_path));

  // Access the custom stream.
  MINIDUMP_DIRECTORY* dir = nullptr;
  void* stream = nullptr;
  ULONG stream_length = 0;
  ASSERT_TRUE(::MiniDumpReadDumpStream(
      const_cast<uint8_t*>(memory_mapped_file.data()), kCustomStreamType, &dir,
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

  bool result = false;
  request().type = MinidumpRequest::SMALL_DUMP_TYPE;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(small_dump_file_path, &result));
  ASSERT_TRUE(result);
  request().type = MinidumpRequest::LARGER_DUMP_TYPE;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(larger_dump_file_path, &result));
  ASSERT_TRUE(result);
  request().type = MinidumpRequest::FULL_DUMP_TYPE;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(full_dump_file_path, &result));
  ASSERT_TRUE(result);

  // Use the relative file sizes to infer that the correct minidump type was
  // respected.
  // Other approaches (testing the memory ranges included in the dump) were
  // rejected due to the difficulty of deterministically knowing what should and
  // shouldn't be included in the various dump types.
  int64_t small_dump_size = 0;
  int64_t larger_dump_size = 0;
  int64_t full_dump_size = 0;

  ASSERT_TRUE(base::GetFileSize(small_dump_file_path, &small_dump_size));
  ASSERT_TRUE(base::GetFileSize(larger_dump_file_path, &larger_dump_size));
  ASSERT_TRUE(base::GetFileSize(full_dump_file_path, &full_dump_size));

  EXPECT_GT(full_dump_size, larger_dump_size);
  EXPECT_GT(larger_dump_size, small_dump_size);
}

TEST_F(MinidumpTest, MemoryRanges) {
  // Generate a minidump for the current process.
  base::FilePath default_dump_file_path = temp_dir().Append(L"default.dump");
  base::FilePath dump_with_memory_range_file_path =
      temp_dir().Append(L"with_range.dump");

  bool result = false;
  ASSERT_NO_FATAL_FAILURE(
      CallGenerateMinidump(default_dump_file_path, &result));
  ASSERT_TRUE(result);

  MinidumpRequest::MemoryRange range = {
      reinterpret_cast<uint32_t>(kGlobalString), sizeof(kGlobalString)};
  request().user_selected_memory_ranges.push_back(range);
  ASSERT_NO_FATAL_FAILURE(
      CallGenerateMinidump(dump_with_memory_range_file_path, &result));
  ASSERT_TRUE(result);

  std::string default_dump;
  std::string dump_with_memory_range;
  ASSERT_TRUE(base::ReadFileToString(default_dump_file_path, &default_dump));
  ASSERT_TRUE(base::ReadFileToString(dump_with_memory_range_file_path,
                                     &dump_with_memory_range));

  ASSERT_EQ(std::string::npos, default_dump.find(kGlobalString));
  ASSERT_NE(std::string::npos, dump_with_memory_range.find(kGlobalString));
}

TEST_F(MinidumpTest, OverwriteExistingFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir.path(), &dump_file_path));

  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, &result));
  ASSERT_TRUE(result);

  ASSERT_HRESULT_SUCCEEDED(
      testing::VisitMinidump(dump_file_path, base::Bind(&ValidateMinidump)));
}

TEST_F(MinidumpTest, NonexistantTargetDirectory) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(
      temp_dir.path().Append(L"Foobar").Append(L"HelloWorld"), &result));
  ASSERT_FALSE(result);
}

// Tests that the ranges for loader lock and the loader lock debug info is
// included in the minidump.
TEST_F(MinidumpTest, LoaderLock) {
  // Generate a minidump for the current process.
  base::FilePath default_dump_file_path = temp_dir().Append(L"default.dump");
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(
      CallGenerateMinidump(default_dump_file_path, &result));
  ASSERT_TRUE(result);

  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(default_dump_file_path));

  minidump::Minidump::Stream stream =
      minidump.FindNextStream(nullptr, MemoryListStream);
  ASSERT_TRUE(stream.IsValid());

  bool loader_lock_found = false;
  bool debug_info_found = false;
  core::AddressRange<uint32_t, uint32_t> loader_lock_range(
      reinterpret_cast<uint32_t>(GetLoaderLock()), sizeof(CRITICAL_SECTION));
  core::AddressRange<uint32_t, uint32_t> debug_info_range(
      reinterpret_cast<uint32_t>(GetLoaderLock()->DebugInfo),
      sizeof(CRITICAL_SECTION_DEBUG));

  ULONG32 num_memory_descriptors = 0;
  stream.ReadAndAdvanceElement(&num_memory_descriptors);
  for (size_t i = 0;
       i < num_memory_descriptors && !(loader_lock_found && debug_info_found);
       ++i) {
    MINIDUMP_MEMORY_DESCRIPTOR memory_descriptor = {};
    stream.ReadAndAdvanceElement(&memory_descriptor);
    core::AddressRange<uint32_t, uint32_t> descriptor_range(
        memory_descriptor.StartOfMemoryRange,
        memory_descriptor.Memory.DataSize);

    // It is possible that adjacent ranges have been merged in the minidump so
    // comparing start address and size might not work.
    if (!loader_lock_found && descriptor_range.Contains(loader_lock_range))
      loader_lock_found = true;
    if (!debug_info_found && descriptor_range.Contains(debug_info_range))
      debug_info_found = true;
  }

  ASSERT_TRUE(loader_lock_found && debug_info_found);
}

// When generating the minidump, it is assumed that ntdll is always loaded at
// the same address in all processes on the system. This test is to make sure
// the assertion never changes in the future.
TEST_F(MinidumpTest, NtdllLoadAddress) {
  // Generate a minidump for the current process.
  base::FilePath dump_file_path = temp_dir().Append(L"default.dump");
  bool result = false;
  ASSERT_NO_FATAL_FAILURE(CallGenerateMinidump(dump_file_path, &result));
  ASSERT_TRUE(result);

  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file_path));

  // Retrieve the unique module list stream.
  minidump::Minidump::Stream module_list =
      minidump.FindNextStream(nullptr, ModuleListStream);
  ASSERT_TRUE(module_list.IsValid());

  ULONG32 num_modules = 0;
  ASSERT_TRUE(module_list.ReadAndAdvanceElement(&num_modules));

  bool ntdll_found = false;
  for (size_t i = 0; i < num_modules; ++i) {
    MINIDUMP_MODULE module = {};
    ASSERT_TRUE(module_list.ReadAndAdvanceElement(&module));

    // Get the module name. The length of the name is included in the stream.
    MINIDUMP_LOCATION_DESCRIPTOR name_location = {static_cast<ULONG32>(-1),
                                                  module.ModuleNameRva};
    minidump::Minidump::Stream name_stream =
        minidump.GetStreamFor(name_location);
    ASSERT_TRUE(name_stream.IsValid());

    std::wstring module_name;
    ASSERT_TRUE(name_stream.ReadAndAdvanceString(&module_name));

    if (module_name.find(L"ntdll.dll") != -1) {
      MODULEINFO ntdll_module_info = {};
      ASSERT_TRUE(::GetModuleInformation(
          ::GetCurrentProcess(), ::GetModuleHandle(L"ntdll.dll"),
          &ntdll_module_info, sizeof(MODULEINFO)));
      ASSERT_EQ(reinterpret_cast<uintptr_t>(ntdll_module_info.lpBaseOfDll),
                module.BaseOfImage);
      ntdll_found = true;
      break;
    }
  }
  // Don't succeed if the address hasn't been checked.
  ASSERT_TRUE(ntdll_found);
}

}  // namespace kasko
