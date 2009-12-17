// Copyright 2009 Google Inc.
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
// Kernel log consumer implementation.
#include "sawbuck/viewer/kernel_log_consumer.h"
#include "base/logging.h"
#include <initguid.h>  // NOLINT - must be last include.

namespace {
// These structures and GUIDs are gleaned from the system.tfm file
// that ships with Debugging Tools For Windows. In some cases the
// formats declared there are not in strict accordance with reality
// in which case there has been some sleauthing around hex dumps of
// the messages to infer the real truth.

DEFINE_GUID(kEventTraceEventClass,
  0x68fdd900, 0x4a3e, 0x11d1, 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3);

enum {
  kLogFileHeaderEvent = 0,
};

struct LogFileHeader32 {
  ULONG BufferSize;
  ULONG Version;
  ULONG BuildNumber;
  ULONG NumProc;
  ULONGLONG EndTime;
  ULONG TimerResolution;
  ULONG MaxFileSize;
  ULONG LogFileMode;
  ULONG BuffersWritten;
  ULONG StartBuffers;
  ULONG PointerSize;
  ULONG EventsLost;
  ULONG CPUSpeed;
  ULONG LoggerName;
  ULONG LogFileName;
  char TimeZone[176];
  ULONGLONG BootTime;
  ULONGLONG PerfFrequency;
  ULONGLONG StartTime;
  ULONG ReservedFlags;
  ULONG BuffersLost;
};

struct LogFileHeader64 {
  ULONG BufferSize;
  ULONG Version;
  ULONG BuildNumber;
  ULONG NumProc;
  ULONGLONG EndTime;
  ULONG TimerResolution;
  ULONG MaxFileSize;
  ULONG LogFileMode;
  ULONG BuffersWritten;
  ULONG StartBuffers;
  ULONG PointerSize;
  ULONG EventsLost;
  ULONG CPUSpeed;
  ULONGLONG LoggerName;
  ULONGLONG LogFileName;
  char TimeZone[176];
  ULONGLONG BootTime;
  ULONGLONG PerfFrequency;
  ULONGLONG StartTime;
  ULONG ReservedFlags;
  ULONG BuffersLost;
};

DEFINE_GUID(kImageLoadEventClass,
  0x2cb15d1d, 0x5fc1, 0x11d2, 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18);

enum {
  kImageNotifyUnloadEvent = 2,
  kImageNotifyIsLoadedEvent = 3,
  kImageNotifyLoadEvent = 10,
};

struct ImageLoad32V0 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  wchar_t ImageFileName[1];
};

// The functions named ConvertModuleInformationFromLogEvent below all serve
// the purpose of parsing a particular version and bitness of an NT Kernel
// Logger module information event to the common ModuleInformation format.
bool ConvertModuleInformationFromLogEvent(
    const ImageLoad32V0* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

struct ImageLoad64V0 {
  ULONGLONG BaseAddress;
  ULONG ModuleSize;
  wchar_t ImageFileName[1];
};

bool ConvertModuleInformationFromLogEvent(
    const ImageLoad64V0* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

struct ImageLoad32V1 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  wchar_t ImageFileName[1];
};

bool ConvertModuleInformationFromLogEvent(
    const ImageLoad32V1* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  *process_id = data->ProcessId;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

struct ImageLoad64V1 {
  ULONGLONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  wchar_t ImageFileName[1];
};

bool ConvertModuleInformationFromLogEvent(
    const ImageLoad64V1* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  *process_id = data->ProcessId;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

struct ImageLoad32V2 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  ULONG Reserved0;
  ULONG DefaultBase;
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  ULONG Reserved4;
  wchar_t ImageFileName[1];
};

bool ConvertModuleInformationFromLogEvent(
    const ImageLoad32V2* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  *process_id = data->ProcessId;
  info->image_checksum = data->ImageChecksum;
  info->time_date_stamp = data->TimeDateStamp;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

struct ImageLoad64V2 {
  ULONGLONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  ULONG Reserved0;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  ULONGLONG DefaultBase;
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  ULONG Reserved4;
  wchar_t ImageFileName[1];
};

bool ConvertModuleInformationFromLogEvent(
    const ImageLoad64V2* data, size_t data_len, DWORD* process_id,
    KernelModuleEvents::ModuleInformation* info) {
  DCHECK(data != NULL && info != NULL);
  if (data_len < FIELD_OFFSET(ImageLoad32V0, ImageFileName))
    return false;

  info->base_address = data->BaseAddress;
  info->module_size = data->ModuleSize;
  *process_id = data->ProcessId;
  info->image_checksum = data->ImageChecksum;
  info->time_date_stamp = data->TimeDateStamp;
  size_t max_len = (data_len -
      FIELD_OFFSET(ImageLoad32V0, ImageFileName)) / sizeof(wchar_t);
  size_t string_len = wcsnlen_s(data->ImageFileName, max_len);
  info->image_file_name.assign(data->ImageFileName, string_len);

  return true;
}

}  // namespace

KernelLogConsumer* KernelLogConsumer::current_ = NULL;

KernelLogConsumer::KernelLogConsumer() : module_event_sink_(NULL),
    is_64_bit_log_(false) {
  DCHECK(current_ == NULL);
  current_ = this;
}

KernelLogConsumer::~KernelLogConsumer() {
  DCHECK(current_ == this);
  current_ = NULL;
}

#define EVENT_HANDLER(type, version, event_type, handler) \
  if (event->Header.Class.Type == type && \
      event->Header.Class.Version == version) { \
    event_type* data = reinterpret_cast<event_type*>(event->MofData); \
    KernelModuleEvents::ModuleInformation info = {}; \
    DWORD process_id = 0; \
    if (ConvertModuleInformationFromLogEvent(data, \
                                             event->MofLength, \
                                             &process_id, \
                                             &info)) { \
      if (process_id == 0) \
        process_id = event->Header.ProcessId; \
      module_event_sink_->handler(process_id, time, info); \
    } \
  }

void KernelLogConsumer::ProcessOneEvent(EVENT_TRACE* event) {
  base::Time time;
  time.FromFileTime(reinterpret_cast<FILETIME&>(event->Header.TimeStamp));
  if (event->Header.Guid == kImageLoadEventClass) {
    if (is_64_bit_log_) {
      EVENT_HANDLER(kImageNotifyUnloadEvent, 0, ImageLoad64V0, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 0, ImageLoad64V0, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 0, ImageLoad64V0, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 1, ImageLoad64V1, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 1, ImageLoad64V1, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 1, ImageLoad64V1, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 2, ImageLoad64V2, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 2, ImageLoad64V2, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 2, ImageLoad64V2, OnModuleLoad);
    } else {
      EVENT_HANDLER(kImageNotifyUnloadEvent, 0, ImageLoad32V0, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 0, ImageLoad32V0, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 0, ImageLoad32V0, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 1, ImageLoad32V1, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 1, ImageLoad32V1, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 1, ImageLoad32V1, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 2, ImageLoad32V2, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 2, ImageLoad32V2, OnModuleLoad)
      EVENT_HANDLER(kImageNotifyLoadEvent, 2, ImageLoad32V2, OnModuleLoad);
    }
  } else if (event->Header.Guid == kEventTraceEventClass) {
    if (event->Header.Class.Type == kLogFileHeaderEvent) {
      LogFileHeader32* data =
          reinterpret_cast<LogFileHeader32*>(event->MofData);

      if (data->PointerSize == 8) {
        is_64_bit_log_ = true;
      }
    }
  }
}

void KernelLogConsumer::ProcessEvent(EVENT_TRACE* event) {
  DCHECK(current_ != NULL);
  current_->ProcessOneEvent(event);
}

DWORD WINAPI KernelLogConsumer::ThreadProc(void* param) {
  KernelLogConsumer* consumer =
      reinterpret_cast<KernelLogConsumer*>(param);

  return consumer->Consume();
}
