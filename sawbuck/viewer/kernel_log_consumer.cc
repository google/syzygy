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
#include <initguid.h>  // NOLINT - must precede kernel_log_types.
#include "sawbuck/viewer/kernel_log_types.h"  // NOLINT - must be last

namespace {

using namespace kernel_log_types;

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
  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  if (event->Header.Guid == kImageLoadEventClass) {
    if (is_64_bit_log_) {
      EVENT_HANDLER(kImageNotifyUnloadEvent, 0, ImageLoad64V0, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 0, ImageLoad64V0,
          OnModuleIsLoaded)
      EVENT_HANDLER(kImageNotifyLoadEvent, 0, ImageLoad64V0, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 1, ImageLoad64V1, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 1, ImageLoad64V1,
          OnModuleIsLoaded)
      EVENT_HANDLER(kImageNotifyLoadEvent, 1, ImageLoad64V1, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 2, ImageLoad64V2, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 2, ImageLoad64V2,
          OnModuleIsLoaded)
      EVENT_HANDLER(kImageNotifyLoadEvent, 2, ImageLoad64V2, OnModuleLoad);
    } else {
      EVENT_HANDLER(kImageNotifyUnloadEvent, 0, ImageLoad32V0, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 0, ImageLoad32V0,
          OnModuleIsLoaded)
      EVENT_HANDLER(kImageNotifyLoadEvent, 0, ImageLoad32V0, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 1, ImageLoad32V1, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 1, ImageLoad32V1,
          OnModuleIsLoaded)
      EVENT_HANDLER(kImageNotifyLoadEvent, 1, ImageLoad32V1, OnModuleLoad);
      EVENT_HANDLER(kImageNotifyUnloadEvent, 2, ImageLoad32V2, OnModuleUnload)
      EVENT_HANDLER(kImageNotifyIsLoadedEvent, 2, ImageLoad32V2,
          OnModuleIsLoaded)
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
