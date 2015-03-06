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
#include <DbgHelp.h>

#include "base/files/file.h"
#include "base/process/process_handle.h"
#include "base/win/scoped_handle.h"

#include "syzygy/common/com_utils.h"

namespace kasko {

bool GenerateMinidump(const base::FilePath& destination,
                      base::ProcessId target_process_id,
                      base::PlatformThreadId thread_id,
                      unsigned long client_exception_pointers,
                      const std::vector<CustomStream>& custom_streams) {
  base::win::ScopedHandle target_process_handle(
      ::OpenProcess(GENERIC_ALL, FALSE, target_process_id));
  if (!target_process_handle) {
    LOG(ERROR) << "Failed to open target process: " << ::common::LogWe() << ".";
    return false;
  }

  MINIDUMP_EXCEPTION_INFORMATION* dump_exception_pointers = NULL;
  MINIDUMP_EXCEPTION_INFORMATION dump_exception_info;

  if (client_exception_pointers) {
    dump_exception_info.ThreadId = thread_id;
    dump_exception_info.ExceptionPointers =
        reinterpret_cast<PEXCEPTION_POINTERS>(client_exception_pointers);
    dump_exception_info.ClientPointers = true;

    dump_exception_pointers = &dump_exception_info;
  }

  base::File destination_file(destination, static_cast<base::File::Flags>(
                                               base::File::FLAG_CREATE_ALWAYS |
                                               base::File::FLAG_WRITE));
  if (!destination_file.IsValid()) {
    LOG(ERROR) << "Failed to create destination file: " << destination.value();
    return false;
  }

  std::vector<MINIDUMP_USER_STREAM> user_streams;
  for (const auto& custom_stream : custom_streams) {
    MINIDUMP_USER_STREAM user_stream = {custom_stream.type,
                                        custom_stream.length,
                                        const_cast<void*>(custom_stream.data)};
    user_streams.push_back(user_stream);
  }

  MINIDUMP_USER_STREAM_INFORMATION
        user_stream_information = {custom_streams.size(), user_streams.data()};

  if (::MiniDumpWriteDump(
          target_process_handle, target_process_id,
          destination_file.GetPlatformFile(),
          static_cast<MINIDUMP_TYPE>(MiniDumpWithProcessThreadData |
                                     MiniDumpWithUnloadedModules |
                                     MiniDumpWithIndirectlyReferencedMemory),
          dump_exception_pointers, &user_stream_information, NULL) == FALSE) {
    LOG(ERROR) << "MiniDumpWriteDump failed: " << ::common::LogWe() << ".";
    return false;
  }

  return true;
}

}  // namespace kasko
