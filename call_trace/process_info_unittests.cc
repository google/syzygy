// Copyright 2011 Google Inc.
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

#include "syzygy/call_trace/process_info.h"

#include <psapi.h>

#include "gtest/gtest.h"
#include "syzygy/pe/pe_file.h"

namespace call_trace {
namespace service {

TEST(ProcessInfoTest, CurrentProcess) {
  HANDLE process = ::GetCurrentProcess();
  ASSERT_TRUE(process != NULL);

  HMODULE module = GetModuleHandle(NULL);
  ASSERT_TRUE(module != NULL);

  MODULEINFO module_info;
  ASSERT_TRUE(::GetModuleInformation(process, module, &module_info,
                                     sizeof(module_info)));

  wchar_t executable_path[MAX_PATH];
  DWORD length = ::GetModuleFileName(module, &executable_path[0],
                                     arraysize(executable_path));
  ASSERT_TRUE(length != 0);
  ASSERT_LT(length, arraysize(executable_path));

  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(FilePath(executable_path)));
  pe::PEFile::Signature pe_sig;
  pe_file.GetSignature(&pe_sig);

  ProcessInfo process_info;
  ASSERT_TRUE(process_info.Initialize(::GetCurrentProcessId()));

  ASSERT_STREQ(process_info.command_line.c_str(), ::GetCommandLineW());
  ASSERT_STREQ(process_info.executable_path.value().c_str(), executable_path);
  ASSERT_EQ(
      reinterpret_cast<void*>(process_info.exe_base_address),
      module_info.lpBaseOfDll);
  ASSERT_EQ(process_info.exe_image_size, module_info.SizeOfImage);
  ASSERT_EQ(process_info.exe_checksum, pe_sig.module_checksum);
  ASSERT_EQ(process_info.exe_time_date_stamp, pe_sig.module_time_date_stamp);

  process_info.Reset();
  ASSERT_TRUE(process_info.process_id == 0);
  ASSERT_FALSE(process_info.process_handle.IsValid());
  ASSERT_TRUE(process_info.executable_path.empty());
  ASSERT_TRUE(process_info.command_line.empty());
  ASSERT_TRUE(process_info.exe_base_address == 0);
  ASSERT_TRUE(process_info.exe_image_size == 0);
  ASSERT_TRUE(process_info.exe_checksum == 0);
  ASSERT_TRUE(process_info.exe_time_date_stamp == 0);
}

}  // namespace call_trace::service
}  // namespace call_trace
