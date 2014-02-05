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

#ifndef SYZYGY_TRACE_SERVICE_PROCESS_INFO_H_
#define SYZYGY_TRACE_SERVICE_PROCESS_INFO_H_

#include <windows.h>
#include <string>

#include "base/basictypes.h"
#include "base/files/file_path.h"
#include "base/win/scoped_handle.h"

namespace trace {
namespace service {

// This class retrieves and encapsulates the process related information
// captured within a trace file. This needs to be a superset of
// pe::PEFile::Signature, which contains the minimum amount of information
// necessary for uniquely identifying a PE file, and the PDB file referring to
// it. This is necessary to allow us to match events up to modules when parsing
// call trace logs.
//
// Usage:
//
//   trace::service::ProcessInfo info;
//   if (!info.Initialize(some_pid)) {
//     LOG(ERROR) << "Failed to retrieve process info.";
//   } else {
//     LOG(INF0) << "Process ID = " << info.process_id;
//     LOG(INFO) << "Executable = " << info.exectuable_path;
//     LOG(INFO) << "Command Line = " << info.command_line;
//     LOG(INFO) << "Base Address = " << info.exe_base_address;
//     LOG(INFO) << "Image Size = " << info.exe_image_size;
//     LOG(INFO) << "Image Checksum = " << info.exe_checksum;
//     LOG(INFO) << "Image Time/Date Stamp = " << info.exe_time_date_stamp;
//   }
struct ProcessInfo {
 public:
  ProcessInfo();
  ~ProcessInfo();

  // Retrieves all the relevant process info concerning @p pid, returning
  // true on success.
  bool Initialize(uint32 pid);

  // Return this ProcessInfo struct to the state it had just following
  // construction.
  void Reset();

  // A handle to the process;
  base::win::ScopedHandle process_handle;

  // The process ID;
  uint32 process_id;

  // The full path to the executable for the process.
  base::FilePath executable_path;

  // The command line for the process.
  std::wstring command_line;

  // The environment block of the process. This is a sequence of wide strings,
  // each of which is terminated by a single NULL. The entire sequence is
  // terminated by a double NULL.
  std::vector<wchar_t> environment;

  // System information.
  OSVERSIONINFOEX os_version_info;
  SYSTEM_INFO system_info;
  MEMORYSTATUSEX memory_status;

  // The base address at which the executable image is currently loaded.
  uint32 exe_base_address;

  // The size of the executable image loaded at exe_base_address.
  uint32 exe_image_size;

  // The checksum of the executable, taken from the NT headers.
  uint32 exe_checksum;

  // The time/date stamp of the executable, taken from the NT headers.
  uint32 exe_time_date_stamp;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProcessInfo);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_PROCESS_INFO_H_
