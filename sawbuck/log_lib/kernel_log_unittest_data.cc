// Copyright 2010 Google Inc.
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
// Test data for kernel log unittest.
#include "sawbuck/log_lib/kernel_log_unittest_data.h"

namespace testing {

const sym_util::ModuleInformation module_list[] = {
  {
    0x01160000, // base_address
    0x0019E000, // module_size
    0x4BA26867, // image_checksum
    0xCAFEBABE, // time_date_stamp
    L"C:\\code\\sawbuck\\src\\sawbuck\\Debug\\"
        L"test_program.exe", // image_file_name
  },
  {
    0x76E10000, // base_address
    0x00127000, // module_size
    0x4791A7A6, // image_checksum
    0x00135D86, // time_date_stamp
    L"C:\\Windows\\system32\\ntdll.dll", // image_file_name
  },
  {
    0x75680000, // base_address
    0x000DB000, // module_size
    0x49953395, // image_checksum
    0x000DC23C, // time_date_stamp
    L"C:\\Windows\\system32\\kernel32.dll", // image_file_name
  },
  {
    0x73CB0000, // base_address
    0x00032000, // module_size
    0x4791A7B6, // image_checksum
    0x0003A724, // time_date_stamp
    L"C:\\Windows\\system32\\WINMM.dll", // image_file_name
  },
  {
    0x76B00000, // base_address
    0x000AA000, // module_size
    0x4791A727, // image_checksum
    0x000AF8AE, // time_date_stamp
    L"C:\\Windows\\system32\\msvcrt.dll", // image_file_name
  },
  {
    0x76D70000, // base_address
    0x0009D000, // module_size
    0x4791A773, // image_checksum
    0x000A8708, // time_date_stamp
    L"C:\\Windows\\system32\\USER32.dll", // image_file_name
  },
  {
    0x75E00000, // base_address
    0x0004B000, // module_size
    0x48FD6647, // image_checksum
    0x00049D43, // time_date_stamp
    L"C:\\Windows\\system32\\GDI32.dll", // image_file_name
  },
  {
    0x76CA0000, // base_address
    0x000C6000, // module_size
    0x4791A64B, // image_checksum
    0x000C31B1, // time_date_stamp
    L"C:\\Windows\\system32\\ADVAPI32.dll", // image_file_name
  },
  {
    0x75CF0000, // base_address
    0x000C2000, // module_size
    0x49F0625F, // image_checksum
    0x000C344A, // time_date_stamp
    L"C:\\Windows\\system32\\RPCRT4.dll", // image_file_name
  },
  {
    0x758E0000, // base_address
    0x00144000, // module_size
    0x4791A74C, // image_checksum
    0x00146AAD, // time_date_stamp
    L"C:\\Windows\\system32\\ole32.dll", // image_file_name
  },
  {
    0x75E50000, // base_address
    0x0008D000, // module_size
    0x4791A74F, // image_checksum
    0x0008FA63, // time_date_stamp
    L"C:\\Windows\\system32\\OLEAUT32.dll", // image_file_name
  },
  {
    0x73C70000, // base_address
    0x00039000, // module_size
    0x4791A74D, // image_checksum
    0x0003B647, // time_date_stamp
    L"C:\\Windows\\system32\\OLEACC.dll", // image_file_name
  },
  {
    0x76F40000, // base_address
    0x00058000, // module_size
    0x4791A75C, // image_checksum
    0x000574F3, // time_date_stamp
    L"C:\\Windows\\system32\\SHLWAPI.dll", // image_file_name
  },
  {
    0x75EE0000, // base_address
    0x00B10000, // module_size
    0x4A573229, // image_checksum
    0x00B0EE79, // time_date_stamp
    L"C:\\Windows\\system32\\SHELL32.dll", // image_file_name
  },
  {
    0x75A30000, // base_address
    0x0001E000, // module_size
    0x4791A715, // image_checksum
    0x000255A7, // time_date_stamp
    L"C:\\Windows\\system32\\IMM32.DLL", // image_file_name
  },
  {
    0x76FA0000, // base_address
    0x000C8000, // module_size
    0x4791A720, // image_checksum
    0x000CCB64, // time_date_stamp
    L"C:\\Windows\\system32\\MSCTF.dll", // image_file_name
  },
  {
    0x76AA0000, // base_address
    0x00009000, // module_size
    0x4791A6E9, // image_checksum
    0x0000A2B7, // time_date_stamp
    L"C:\\Windows\\system32\\LPK.DLL", // image_file_name
  },
  {
    0x769F0000, // base_address
    0x0007D000, // module_size
    0x4791A776, // image_checksum
    0x0007DC08, // time_date_stamp
    L"C:\\Windows\\system32\\USP10.dll", // image_file_name
  },
  {
    0x6C2B0000, // base_address
    0x00023000, // module_size
    0x4AF0FA99, // image_checksum
    0x0002647C, // time_date_stamp
    L"C:\\PROGRA~1\\GOOGLE\\GO333C~1\\GOEC62~1.DLL", // image_file_name
  },
  {
    0x75DD0000, // base_address
    0x0002D000, // module_size
    0x4791A798, // image_checksum
    0x0002E055, // time_date_stamp
    L"C:\\Windows\\system32\\WS2_32.dll", // image_file_name
  },
  {
    0x75DC0000, // base_address
    0x00006000, // module_size
    0x4791A7A4, // image_checksum
    0x000074AE, // time_date_stamp
    L"C:\\Windows\\system32\\NSI.dll", // image_file_name
  },
  {
    0x6FA00000, // base_address
    0x0003E000, // module_size
    0x4AAA262F, // image_checksum
    0x000420DE, // time_date_stamp
    L"C:\\PROGRA~1\\Sophos\\SOPHOS~1\\SOPHOS~1.DLL", // image_file_name
  },
  {
    0x75670000, // base_address
    0x00007000, // module_size
    0x4549BD99, // image_checksum
    0x00009AC8, // time_date_stamp
    L"C:\\Windows\\system32\\PSAPI.DLL", // image_file_name
  },
  {
    0x746A0000, // base_address
    0x0019E000, // module_size
    0x4791A752, // image_checksum
    0x001A2D0F, // time_date_stamp
    L"C:\\Windows\\WinSxS\\x86_microsoft."
        L"windows.common-controls_6595b64144ccf1df_6.0.6001."
        L"18000_none_5cdbaa5a083979cc\\comctl32.dll", // image_file_name
  },
};

const size_t kNumModules = arraysize(module_list);

const KernelProcessEvents::ProcessInfo process_list[] = {
  {
    0,  // process_id
    0,  // parent_id
    4294967295,  // session_id
    {
      1,  // Revision
      1,  // SubAuthorityCount
      { 0, 0, 0, 0, 0, 5 },  // IdentifierAuthority
      { 18 },  // SubAuthority
    },  // user_sid
    "Idle",  // image_name
    L"",  // command_line
  },
  {
    4,  // process_id
    0,  // parent_id
    4294967295,  // session_id
    {
      1,  // Revision
      1,  // SubAuthorityCount
      { 0, 0, 0, 0, 0, 5 },  // IdentifierAuthority
      { 18 },  // SubAuthority
    },  // user_sid
    "System",  // image_name
    L"",  // command_line
  },
  {
    264,  // process_id
    4,  // parent_id
    4294967295,  // session_id
    {
      1,  // Revision
      1,  // SubAuthorityCount
      { 0, 0, 0, 0, 0, 5 },  // IdentifierAuthority
      { 18 },  // SubAuthority
    },  // user_sid
    "smss.exe",  // image_name
    L"\\SystemRoot\\System32\\smss.exe",  // command_line
  },
  {
    1776,  // process_id
    988,  // parent_id
    1,  // session_id
    {
      {
        1,  // Revision
        5,  // SubAuthorityCount
        { 0, 0, 0, 0, 0, 5 },  // IdentifierAuthority
        { 21 },  // SubAuthority
      },  // user_sid
      { 753675414, 103939432, 3550797041, 1000 },  // more_sids
    },
    "notepad.exe",  // image_name
    L"\"C:\\Windows\\system32\\notepad.exe\" ",  // command_line
  },
};

const size_t kNumProcesses = arraysize(process_list);

}  // namespace testing
