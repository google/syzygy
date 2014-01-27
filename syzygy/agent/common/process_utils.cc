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
#include "syzygy/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/client/rpc_session.h"

namespace agent {
namespace common {

namespace {

// Accessing a module acquired from process iteration calls is inherently racy,
// as we don't hold any kind of reference to the module, and so the module
// could be unloaded while we're accessing it.
bool CaptureModuleInformation(const base::win::PEImage& image,
                              size_t* module_base_size,
                              uint32* module_checksum,
                              uint32* module_time_date_stamp) {
  DCHECK(module_base_size != NULL);
  DCHECK(module_checksum != NULL);
  DCHECK(module_time_date_stamp != NULL);

  __try {
    const IMAGE_NT_HEADERS* nt_headers = image.GetNTHeaders();
    *module_base_size = nt_headers->OptionalHeader.SizeOfImage;
    *module_checksum = nt_headers->OptionalHeader.CheckSum;
    *module_time_date_stamp = nt_headers->FileHeader.TimeDateStamp;

    // Make reasonably sure we're actually looking at a module.
    if (!image.VerifyMagic())
      return false;
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

  // See whether we can acquire the module data.
  base::win::PEImage image(module);
  size_t module_base_size = 0;
  uint32 module_checksum = 0;
  uint32 module_time_date_stamp = 0;
  if (!CaptureModuleInformation(image,
                                &module_base_size,
                                &module_checksum,
                                &module_time_date_stamp)) {
    LOG(ERROR) << "Failed to capture module information.";
    return false;
  }

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

  module_event->module_base_addr = module;
  module_event->module_base_size = module_base_size;
  module_event->module_checksum = module_checksum;
  module_event->module_time_date_stamp = module_time_date_stamp;

  wchar_t module_name[MAX_PATH] = { 0 };
  if (::GetMappedFileName(::GetCurrentProcess(), module,
                          module_name, arraysize(module_name)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to get module name: " << ::common::LogWe(error)
               << ".";
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
