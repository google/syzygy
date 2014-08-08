// Copyright 2012 Google Inc. All Rights Reserved.
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
// This file declares the trace::service::ProcessInfo class which
// retrieves and encapsulates the process related information captured
// within a trace file.

#include "syzygy/trace/service/process_info.h"

#include <psapi.h>
#include <winternl.h>

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "syzygy/common/align.h"
#include "syzygy/common/com_utils.h"

// From advapi32.dll, but including ntsecapi.h causes conflicting declarations.
extern "C" ULONG NTAPI LsaNtStatusToWinError(__in NTSTATUS status);

namespace trace {
namespace service {

namespace {

typedef NTSTATUS (NTAPI *FuncPtrNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength);

// Helper function to get the basic process info for pid/handle.
bool GetPBI(uint32 pid, HANDLE handle, PROCESS_BASIC_INFORMATION* pbi) {
  DCHECK(pbi != NULL);

  HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
  if (ntdll == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get ntdll.dll module handle: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  FuncPtrNtQueryInformationProcess query_func =
      reinterpret_cast<FuncPtrNtQueryInformationProcess>(
          ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (query_func == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get NtQueryInformationProcess proc address: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  NTSTATUS status = query_func(handle, 0, pbi, sizeof(*pbi), NULL);
  if (status != 0) {
    LOG(ERROR) << "Failed to query process information for PID=" << pid
               << ": " << ::common::LogWe(::LsaNtStatusToWinError(status))
               << ".";
    return false;
  }

  return true;
}

bool ReadEnvironmentString(HANDLE handle,
                           size_t page_size,
                           const wchar_t* remote_env_string,
                           std::vector<wchar_t>* environment) {
  DCHECK_LT(0u, page_size);
  DCHECK(common::IsPowerOfTwo(page_size));
  DCHECK(remote_env_string != NULL);
  DCHECK(environment != NULL);

  environment->clear();

  std::vector<uint8> vector(page_size);
  uint8* buffer = &vector.at(0);
  const wchar_t* wbuffer = reinterpret_cast<const wchar_t*>(buffer);
  const uint8* remote_cursor =
      reinterpret_cast<const uint8*>(remote_env_string);
  const uint8* next_page = reinterpret_cast<const uint8*>(
      common::AlignUp(reinterpret_cast<size_t>(remote_cursor),
                      page_size));

  size_t nulls_in_a_row = 0;
  while (true) {
    DCHECK_GE(next_page, remote_cursor);
    if (remote_cursor == next_page)
      next_page += page_size;

    // Determine the maximum amount of data to read. We read a page at a
    // time so as to avoid going off the end of addressable memory, something
    // that ReadProcessMemory really hates (it will return zero bytes read and
    // ERROR_PARTIAL_COPY).
    size_t bytes_to_read = next_page - remote_cursor;
    DCHECK_EQ(0u, bytes_to_read % sizeof(wbuffer[0]));

    SIZE_T bytes_read = 0;
    if (!::ReadProcessMemory(handle, remote_cursor, buffer, bytes_to_read,
                             &bytes_read)) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "Failed to read environment string: "
                 << ::common::LogWe(error) << ".";
      return false;
    }
    DCHECK_LT(0u, bytes_read);
    size_t elems_read = bytes_read / sizeof(wbuffer[0]);
    size_t bytes_used = elems_read * sizeof(wbuffer[0]);
    remote_cursor += bytes_used;

    // Look for the terminating double NULL.
    for (size_t i = 0; i < elems_read; ++i) {
      if (wbuffer[i] == 0) {
        if (++nulls_in_a_row == 2) {
          // We found the terminating double NULL. Append the end of the
          // string and we're done.
          environment->insert(environment->end(), wbuffer, wbuffer + i + 1);
          return true;
        }
      } else {
        nulls_in_a_row = 0;
      }
    }

    // If we get here then the entire buffer we just read needs to be appended
    // to the environment string.
    environment->insert(environment->end(), wbuffer, wbuffer + elems_read);
  }

  NOTREACHED();
  return false;
}

// Extract the exe path and command line for the process given by pid/handle.
// Note that there are other ways to retrieve the exe path, but since this
// function will already be spelunking in the same area (to get the command
// line) we just get the exe path while we're there.
bool GetProcessStrings(uint32 pid,
                       HANDLE handle,
                       size_t page_size,
                       base::FilePath* exe_path,
                       std::wstring* cmd_line,
                       std::vector<wchar_t>* environment) {
  DCHECK(exe_path != NULL);
  DCHECK(cmd_line != NULL);
  DCHECK(environment != NULL);

  // Fetch the basic process information.
  PROCESS_BASIC_INFORMATION pbi = {};
  if (!GetPBI(pid, handle, &pbi)) {
    return false;
  }

  // TODO(rogerm): Validate that the target process has the same bitness as
  //     the querying process; otherwise, the following won't work.

  // Setup the variables that we'll use later.
  uint8* peb_base_address = reinterpret_cast<uint8*>(pbi.PebBaseAddress);
  uint8* user_proc_params = NULL;
  UNICODE_STRING string_value[2] = {};

  // Get the address of the process parameters.
  const size_t kProcessParamOffset = FIELD_OFFSET(PEB, ProcessParameters);
  if (!::ReadProcessMemory(handle, peb_base_address + kProcessParamOffset,
                           &user_proc_params, sizeof(user_proc_params), NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read process parameter pointer for PID=" << pid
               << " " << ::common::LogWe(error) << ".";
    return false;
  }

  // Get the image path name and command line UNICODE_STRING structures.
  // string_value[0] will be the image path name, and string_value[1] will
  // be the command line.
  const size_t kImagePathNameOffset =
      FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, ImagePathName);
  if (!::ReadProcessMemory(handle, user_proc_params + kImagePathNameOffset,
                           &string_value[0], sizeof(string_value), NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read the process parameters for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }

  // Read the image path name.
  std::wstring temp_exe_path;
  size_t num_chars_in_path = string_value[0].Length / sizeof(wchar_t);
  if (!::ReadProcessMemory(handle, string_value[0].Buffer,
                           WriteInto(&temp_exe_path, num_chars_in_path + 1),
                           string_value[0].Length, NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read the exe path for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }
  *exe_path = base::FilePath(temp_exe_path);

  // Read the command line.
  size_t num_chars_in_cmd_line = string_value[1].Length / sizeof(wchar_t);
  if (!::ReadProcessMemory(handle, string_value[1].Buffer,
                           WriteInto(cmd_line, num_chars_in_cmd_line + 1),
                           string_value[1].Length, NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read the command line for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }

  // Get the environment string. Note that this a pointer into a remote process
  // so we can't directly dereference it. This is not documented directly in
  // winternl.h, but it is documented here: http://goto.google.com/win-proc-env
  const size_t kEnvironmentStringOffset = 0x48;
  wchar_t* remote_env_string = NULL;
  if (!::ReadProcessMemory(handle, user_proc_params + kEnvironmentStringOffset,
                           &remote_env_string, sizeof(remote_env_string),
                           NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read environment variable string for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }

  // Finally, read the environment string.
  if (!ReadEnvironmentString(handle, page_size, remote_env_string,
                             environment)) {
    return false;
  }

  return true;
}

// Gets the NT headers of the running process.
bool GetProcessNtHeaders(
    uint32 pid, HANDLE handle, IMAGE_NT_HEADERS* nt_headers) {
  DCHECK(nt_headers != NULL);
  HMODULE module = 0;
  DWORD dummy = 0;

  // The first module returned by the enumeration will be the executable. So
  // we only need to ask for one HMODULE.
  if (!::EnumProcessModules(handle, &module, sizeof(module), &dummy)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module handle for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }

  // We now have enough information get the module info for the executable.
  MODULEINFO info = {};
  if (!::GetModuleInformation(handle, module, &info, sizeof(info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module info for PID=" << pid
               << ": " << ::common::LogWe(error) << ".";
    return false;
  }

  uint8* base_addr = reinterpret_cast<uint8*>(info.lpBaseOfDll);

  // Get the DOS header.
  IMAGE_DOS_HEADER dos_header;
  uint8* addr_to_read = base_addr;
  SIZE_T bytes_to_read = sizeof(IMAGE_DOS_HEADER);
  SIZE_T bytes_read = 0;
  if (!::ReadProcessMemory(handle, addr_to_read, &dos_header, bytes_to_read,
                           &bytes_read) ||
      bytes_read != bytes_to_read) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read DOS header for PID=" << pid
               << " " << ::common::LogWe(error) << ".";
    return false;
  }

  // Get the NT headers.
  addr_to_read = base_addr + dos_header.e_lfanew;
  bytes_to_read = sizeof(IMAGE_NT_HEADERS);
  bytes_read = 0;
  if (!::ReadProcessMemory(handle, addr_to_read, nt_headers, bytes_to_read,
                           &bytes_read) ||
      bytes_read != bytes_to_read) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read NT headers for PID=" << pid
               << " " << ::common::LogWe(error) << ".";
    return false;
  }

  return true;
}

}  // namespace

ProcessInfo::ProcessInfo()
    : process_id(0),
      exe_base_address(0),
      exe_image_size(0),
      exe_checksum(0),
      exe_time_date_stamp(0) {
  ::memset(&os_version_info, 0, sizeof(os_version_info));
  ::memset(&system_info, 0, sizeof(system_info));
  ::memset(&memory_status, 0, sizeof(memory_status));
}

ProcessInfo::~ProcessInfo() {
}

void ProcessInfo::Reset() {
  process_handle.Close();
  process_id = 0;
  executable_path.clear();
  command_line.clear();
  environment.clear();
  ::memset(&os_version_info, 0, sizeof(os_version_info));
  ::memset(&system_info, 0, sizeof(system_info));
  ::memset(&memory_status, 0, sizeof(memory_status));
  exe_base_address = 0;
  exe_image_size = 0;
  exe_checksum = 0;
  exe_time_date_stamp = 0;
}

bool ProcessInfo::Initialize(uint32 pid) {
  // TODO(chrisha): This whole mechanism is racy by its very nature, as it
  //     reads memory from a remote process that is running, and which may be
  //     changing the things being read. In practice this has not proved to be
  //     a problem as we are typically running under the loader lock, but this
  //     is not true when running instrumented EXEs. Long term it would be good
  //     to make this run in the instrumented process and have it shuttle the
  //     data across in the first buffer.

  // Open the process given by pid. We need a process handle that (1) remains
  // valid over time (2) lets us query for info about the process, and (3)
  // allows us to read the command line from the process memory.
  const DWORD kFlags =
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

  process_handle.Set(::OpenProcess(kFlags, FALSE, pid));

  if (!process_handle.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to open PID=" << pid << " " << ::common::LogWe(error)
               << ".";
    Reset();
    return false;
  }

  process_id = pid;

  ::GetSystemInfo(&system_info);

  // Get the executable path, command line and environment string.
  if (!GetProcessStrings(process_id, process_handle, system_info.dwPageSize,
                         &executable_path, &command_line, &environment)) {
    Reset();
    return false;
  }

  // Get the operating system and hardware information.
  os_version_info.dwOSVersionInfoSize = sizeof(os_version_info);
  if (!::GetVersionEx(
      reinterpret_cast<OSVERSIONINFO*>(&os_version_info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get OS version information: "
               << ::common::LogWe(error) << ".";
    Reset();
    return false;
  }

  memory_status.dwLength = sizeof(memory_status);
  if (!::GlobalMemoryStatusEx(&memory_status)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get global memory status: "
               << ::common::LogWe(error) << ".";
    Reset();
    return false;
  }

  // Get the headers for the running image and use these to populate various
  // fields.
  IMAGE_NT_HEADERS nt_headers;
  if (!GetProcessNtHeaders(process_id, process_handle, &nt_headers)) {
    Reset();
    return false;
  }
  exe_base_address = nt_headers.OptionalHeader.ImageBase;
  exe_image_size = nt_headers.OptionalHeader.SizeOfImage;
  exe_checksum = nt_headers.OptionalHeader.CheckSum;
  exe_time_date_stamp = nt_headers.FileHeader.TimeDateStamp;

  return true;
}

}  // namespace service
}  // namespace trace
