// Copyright 2012 Google Inc.
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
#include "base/string_util.h"
#include "sawbuck/common/com_utils.h"

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
    LOG(ERROR) << "Failed to get ntdll.dll module handle: " << com::LogWe(error)
               << ".";
    return false;
  }

  FuncPtrNtQueryInformationProcess query_func =
      reinterpret_cast<FuncPtrNtQueryInformationProcess>(
          ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (query_func == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get NtQueryInformationProcess proc address: "
               << com::LogWe(error) << ".";
    return false;
  }

  NTSTATUS status = query_func(handle, 0, pbi, sizeof(*pbi), NULL);
  if (status != 0) {
    LOG(ERROR) << "Failed to query process information for PID=" << pid
               << ": " << com::LogWe(::LsaNtStatusToWinError(status)) << ".";
    return false;
  }

  return true;
}

// Given a process and an address in its internal memory, returns the maximum
// number of bytes owned by the process starting at that address. This is done
// by looking up how many consecutive pages containing the given address are
// allocated by the given process. Returns true on success (with the number of
// bytes that can be safely read in @p size), false otherwise (@p size set to
// zero).
bool GetMaximumMemorySize(HANDLE process, void* remote_address, size_t* size) {
  DCHECK(remote_address != NULL);
  DCHECK(size != NULL);

  *size = 0;

  MEMORY_BASIC_INFORMATION mem_info = {};
  if (VirtualQueryEx(process, remote_address, &mem_info,
                     sizeof(mem_info)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQueryEx failed: " << com::LogWe(error) << ".";
    return false;
  }

  // If the memory contains code or is not readable return an error.
  if (mem_info.Protect == PAGE_NOACCESS || mem_info.Protect == PAGE_EXECUTE) {
    LOG(ERROR) << "Address being dereferenced does not contain readable data.";
    return false;
  }

  // Get the size that may be read after the provided address.
  size_t region_offset = reinterpret_cast<const uint8*>(remote_address) -
      reinterpret_cast<const uint8*>(mem_info.BaseAddress);
  *size = mem_info.RegionSize - region_offset;

  return true;
}

bool ReadEnvironmentString(HANDLE handle,
                           const wchar_t* remote_env_string,
                           size_t max_size,
                           std::vector<wchar_t>* environment) {
  DCHECK(environment != NULL);

  environment->clear();

  const uint8* remote_read_cursor =
      reinterpret_cast<const uint8*>(remote_env_string);
  std::vector<wchar_t> buffer;

  size_t max_elems = max_size / sizeof(buffer[0]);

  // We use a large buffer to minimize calls to ReadProcessMemory.
  size_t buffer_elems = 128 * 1024;
  if (buffer_elems < max_elems)
    buffer_elems = max_elems;
  buffer.resize(buffer_elems);
  size_t elems_left = max_elems;

  size_t nulls_in_a_row = 0;
  while (elems_left > 0) {
    // Figure out how much data to read in this call.
    size_t elems_to_read = buffer.size();
    if (elems_to_read > elems_left)
      elems_to_read = elems_left;
    size_t bytes_to_read = elems_to_read * sizeof(buffer[0]);

    // Read the next chunk of data.
    SIZE_T bytes_read = 0;
    if (!::ReadProcessMemory(handle, remote_read_cursor, &buffer[0],
                             bytes_to_read, &bytes_read)) {
      DWORD error = ::GetLastError();

      // It's possible for us to get a failure with ERROR_PARTIAL_COPY if we're
      // trying to read pages that are not currently mapped to memory or are
      // dirty. Since we do get the number of bytes that were successfully read
      // we can silently ignore this. We'll only bail if we're unable to
      // advance the read cursor at all.
      if (error != ERROR_PARTIAL_COPY) {
        LOG(ERROR) << "Unable to read environment string: " << com::LogWe(error)
                   << ".";
        return false;
      }
    }
    size_t elems_read = bytes_read / sizeof(buffer[0]);
    bytes_read = elems_read * sizeof(buffer[0]);

    // If we got a partial read of zero bytes, we're stuck.
    if (elems_read == 0) {
      LOG(ERROR) << "Unable to read environment string.";
      return false;
    }

    remote_read_cursor += bytes_read;

    // Scan through the buffer looking for the terminating NULLs.
    size_t i = 0;
    for (; i < elems_to_read && nulls_in_a_row < 2; ++i) {
      if (buffer[i] == 0)
        ++nulls_in_a_row;
      else
        nulls_in_a_row = 0;
    }

    environment->insert(environment->end(), buffer.begin(), buffer.begin() + i);

    if (nulls_in_a_row == 2)
      return true;
  }

  LOG(ERROR) << "The environment appears to be malformed.";

  return false;
}

// Extract the exe path and command line for the process given by pid/handle.
// Note that there are other ways to retrieve the exe path, but since this
// function will already be spelunking in the same area (to get the command
// line) we just get the exe path while we're there.
bool GetProcessStrings(uint32 pid,
                       HANDLE handle,
                       FilePath* exe_path,
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

  // Get the address of the process paramters.
  const size_t kProcessParamOffset = FIELD_OFFSET(PEB, ProcessParameters);
  if (!::ReadProcessMemory(handle, peb_base_address + kProcessParamOffset,
                           &user_proc_params, sizeof(user_proc_params),
                           NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read process parameter pointer for PID=" << pid
               << " " << com::LogWe(error) << ".";
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
               << ": " << com::LogWe(error) << ".";
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
               << ": " << com::LogWe(error) << ".";
    return false;
  }
  *exe_path = FilePath(temp_exe_path);

  // Read the command line.
  size_t num_chars_in_cmd_line = string_value[1].Length / sizeof(wchar_t);
  if (!::ReadProcessMemory(handle, string_value[1].Buffer,
                           WriteInto(cmd_line, num_chars_in_cmd_line + 1),
                           string_value[1].Length, NULL)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read the command line for PID=" << pid
               << ": " << com::LogWe(error) << ".";
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
               << ": " << com::LogWe(error) << ".";
    return false;
  }

  // Get an upper bound on the size of the environment string. It doesn't have
  // the size encoded within it directly, and this gives us an upper bound by
  // determining how much data the remote process owns starting at the given
  // location.
  size_t max_size = 0;
  if (!GetMaximumMemorySize(handle, remote_env_string, &max_size))
    return false;

  // Finally, read the environment string.
  if (!ReadEnvironmentString(handle, remote_env_string, max_size, environment))
    return false;

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
               << ": " << com::LogWe(error) << ".";
    return false;
  }

  // We now have enough information get the module info for the executable.
  MODULEINFO info = {};
  if (!::GetModuleInformation(handle, module, &info, sizeof(info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module info for PID=" << pid
               << ": " << com::LogWe(error) << ".";
    return false;
  }

  uint8* base_addr = reinterpret_cast<uint8*>(info.lpBaseOfDll);

  // Get the DOS header.
  IMAGE_DOS_HEADER dos_header;
  uint8* addr_to_read = base_addr;
  SIZE_T bytes_to_read = sizeof(IMAGE_DOS_HEADER);
  SIZE_T bytes_read = 0;
  if (!::ReadProcessMemory(handle, addr_to_read, &dos_header,
                           bytes_to_read, &bytes_read) ||
      bytes_read != bytes_to_read) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read DOS header for PID=" << pid
               << " " << com::LogWe(error) << ".";
    return false;
  }

  // Get the NT headers.
  addr_to_read = base_addr + dos_header.e_lfanew;
  bytes_to_read = sizeof(IMAGE_NT_HEADERS);
  bytes_read = 0;
  if (!::ReadProcessMemory(handle, addr_to_read, nt_headers,
                           bytes_to_read, &bytes_read) ||
      bytes_read != bytes_to_read) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to read NT headers for PID=" << pid
               << " " << com::LogWe(error) << ".";
    return false;
  }

  return true;
}

// Gets the executable module information for the process given by pid/handle.
bool GetMemoryRange(uint32 pid, HANDLE handle, uint32* base_addr,
                    uint32* module_size) {
  DCHECK(base_addr != NULL);
  DCHECK(module_size != NULL);

  HMODULE module = 0;
  DWORD dummy = 0;

  // The first module returned by the enumeration will be the executable. So
  // we only need to ask for one HMODULE.
  if (!::EnumProcessModules(handle, &module, sizeof(module), &dummy)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module handle for PID=" << pid
               << ": " << com::LogWe(error) << ".";
    return false;
  }

  // We now have enough information get the module info for the executable.
  MODULEINFO info = {};
  if (!::GetModuleInformation(handle, module, &info, sizeof(info))) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module info for PID=" << pid
               << ": " << com::LogWe(error) << ".";
    return false;
  }

  *base_addr = reinterpret_cast<uint32>(info.lpBaseOfDll);
  *module_size = info.SizeOfImage;

  return true;
}

}  // namespace

ProcessInfo::ProcessInfo()
    : process_id(0),
      exe_base_address(0),
      exe_image_size(0),
      exe_checksum(0),
      exe_time_date_stamp(0) {
}

ProcessInfo::~ProcessInfo() {
}

void ProcessInfo::Reset() {
  process_handle.Close();
  process_id = 0;
  executable_path.clear();
  command_line.clear();
  environment.clear();
  exe_base_address = 0;
  exe_image_size = 0;
  exe_checksum = 0;
  exe_time_date_stamp = 0;
}

bool ProcessInfo::Initialize(uint32 pid) {
  // Open the process given by pid. We need a process handle that (1) remains
  // valid over time (2) lets us query for info about the process, and (3)
  // allows us to read the command line from the process memory.
  const DWORD kFlags =
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  process_handle.Set(::OpenProcess(kFlags, FALSE, pid));
  if (!process_handle.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to open PID=" << pid << " " << com::LogWe(error)
               << ".";
    Reset();
    return false;
  }

  process_id = pid;

  // Get the executable path and command line.
  if (!GetProcessStrings(process_id, process_handle,
                         &executable_path, &command_line, &environment)) {
    Reset();
    return false;
  }

  // Get the base address and module size.
  if (!GetMemoryRange(process_id, process_handle,
                      &exe_base_address, &exe_image_size)) {
    Reset();
    return false;
  }

  // Get the headers for the running image and use these to populate the
  // checksum and time-date stamp.
  IMAGE_NT_HEADERS nt_headers;
  if (!GetProcessNtHeaders(process_id, process_handle, &nt_headers)) {
    Reset();
    return false;
  }
  exe_checksum = nt_headers.OptionalHeader.CheckSum;
  exe_time_date_stamp = nt_headers.FileHeader.TimeDateStamp;

  return true;
}

}  // namespace trace::service
}  // namespace trace
