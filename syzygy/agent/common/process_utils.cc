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

#include "syzygy/agent/common/process_utils.h"

#include <psapi.h>

#include "base/logging.h"
#include "base/win/pe_image.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/client/rpc_session.h"

namespace agent {
namespace common {

namespace {

// Accessing a module acquired from process iteration calls is inherently racy,
// as we don't hold any kind of reference to the module, and so the module
// could be unloaded while we're accessing it. In practice this shouldn't
// happen to us, as we'll be running under the loader's lock in all cases.
bool CaptureModuleInformation(const IMAGE_NT_HEADERS* nt_headers,
                              TraceModuleData* module_event) {
  DCHECK(nt_headers != NULL);
  DCHECK(module_event != NULL);

  __try {
    module_event->module_base_size = nt_headers->OptionalHeader.SizeOfImage;
    module_event->module_checksum = nt_headers->OptionalHeader.CheckSum;
    module_event->module_time_date_stamp = nt_headers->FileHeader.TimeDateStamp;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }

  return true;
}

}  // namespace

void GetProcessModules(ModuleVector* modules) {
  DCHECK(modules != NULL);

  modules->resize(128);
  while (true) {
    DWORD bytes = sizeof(modules->at(0)) * modules->size();
    DWORD needed_bytes = 0;
    BOOL success = ::EnumProcessModules(::GetCurrentProcess(),
                                        &modules->at(0),
                                        bytes,
                                        &needed_bytes);
    if (success && bytes >= needed_bytes) {
      // Success - break out of the loop.
      // Resize our module vector to the returned size.
      modules->resize(needed_bytes / sizeof(modules->at(0)));
      return;
    }

    // Resize our module vector with the needed size and little slop.
    modules->resize(needed_bytes / sizeof(modules->at(0)) + 4);
  }
}

bool LogModule(HMODULE module,
               trace::client::RpcSession* session,
               trace::client::TraceFileSegment* segment) {
  DCHECK(module != NULL);
  DCHECK(session != NULL);
  DCHECK(segment != NULL);

  // Make sure the event we're about to write will fit.
  if (!segment->CanAllocate(sizeof(TraceModuleData)) ||
      !session->ExchangeBuffer(segment)) {
    // Failed to allocate a new segment.
    LOG(ERROR) << "Failed to exchange buffer.";
    return false;
  }

  DCHECK(segment->CanAllocate(sizeof(TraceModuleData)));

  // Allocate a record in the log.
  TraceModuleData* module_event = reinterpret_cast<TraceModuleData*>(
      segment->AllocateTraceRecordImpl(
          TRACE_PROCESS_ATTACH_EVENT, sizeof(TraceModuleData)));
  DCHECK(module_event != NULL);

  // Populate the log record.
  base::win::PEImage image(module);
  module_event->module_base_addr = module;
  if (!CaptureModuleInformation(image.GetNTHeaders(), module_event)) {
    LOG(ERROR) << "Failed to capture module information.";
    return false;
  }

  wchar_t module_name[MAX_PATH] = { 0 };
  if (::GetMappedFileName(::GetCurrentProcess(), module,
                          module_name, arraysize(module_name)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module name: " << com::LogWe(error) << ".";
    return false;
  }
  base::FilePath device_path(module_name);
  base::FilePath drive_path;
  if (!::common::ConvertDevicePathToDrivePath(device_path, &drive_path)) {
    LOG(ERROR) << "ConvertDevicePathToDrivePath failed.";
    return false;
  }
  ::wcsncpy(module_event->module_name, drive_path.value().c_str(),
            arraysize(module_event->module_name));

  module_event->module_exe[0] = L'\0';

  return true;
}

}  // namespace common
}  // namespace agent
