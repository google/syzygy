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
//
// This file declares the call_trace::service::ProcessInfo class which
// retrieves and encapsulates the process related information captured
// within a trace file.

#ifndef SYZYGY_CALL_TRACE_PROCESS_INFO_H_
#define SYZYGY_CALL_TRACE_PROCESS_INFO_H_

#include <string>

#include "base/basictypes.h"
#include "base/file_path.h"
#include "base/win/scoped_handle.h"

namespace call_trace {
namespace service {

// This class retrieves and encapsulates the process related information
// captured within a trace file.
//
// Usage:
//
//   call_trace::service::ProcessInfo info;
//   if (!info.Initialize(some_pid)) {
//     LOG(ERROR) << "Failed to retrieve process info.";
//   } else {
//     LOG(INF0) << "Process ID = " << info.process_id;
//     LOG(INFO) << "Executable = " << info.exectuable_path;
//     LOG(INFO) << "Command Line = " << info.command_line;
//     LOG(INFO) << "Base Address = " << info.exe_base_address;
//     LOG(INFO) << "Image Size = " << info.exe_image_size;
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
  FilePath executable_path;

  // The command line for the process.
  std::wstring command_line;

  // The base address at which the executable image is currently loaded.
  uint32 exe_base_address;

  // The size of the executable image loaded at exe_base_address.
  uint32 exe_image_size;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProcessInfo);
};

}  // namespace call_trace::service
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_PROCESS_INFO_H_
