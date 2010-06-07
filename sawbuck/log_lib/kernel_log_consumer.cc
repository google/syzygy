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
#include "sawbuck/log_lib/kernel_log_consumer.h"

#include "base/logging.h"
#include "sawbuck/log_lib/buffer_parser.h"
#include <initguid.h>  // NOLINT - must precede kernel_log_types.
#include "sawbuck/log_lib/kernel_log_types.h"  // NOLINT - must be last

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

// A traits class to deal with the minor differences in event parsing.
template <class ProcessInfoType>
class ProcessInfoTypeTraits {
 public:
  static const bool has_command_line = true;
};

template <>
class ProcessInfoTypeTraits<ProcessInfo32V0> {
 public:
  static const bool has_command_line = false;
};

template <>
class ProcessInfoTypeTraits<ProcessInfo32V1> {
 public:
  static const bool has_command_line = false;
};

template <>
class ProcessInfoTypeTraits<ProcessInfo64V1> {
 public:
  static const bool has_command_line = false;
};

template <class ProcessInfoType>
bool ParseProcessEvent(const void* data, size_t data_len,
    KernelProcessEvents::ProcessInfo* process_info, DWORD* exit_status) {
  BinaryBufferReader reader(data, data_len);
  const ProcessInfoType* info = NULL;
  // Probe the info struct header and a get a pointer to it.
  if (!reader.Read(FIELD_OFFSET(ProcessInfoType, UserSID), &info))
    return false;

  // Probe the front of the SID structure.
  const SID* sid = NULL;
  if (!reader.Peek(FIELD_OFFSET(SID, SubAuthority), &sid) ||
      !::IsValidSid(const_cast<SID*>(sid)))
    return false;

  // Calculate the SID length and walk past it.
  DCHECK_EQ(&info->UserSID, sid);
  DWORD sid_len = ::GetLengthSid(const_cast<SID*>(sid));
  if (!reader.Consume(sid_len))
    return false;

  // Retrieve the trailing image name.
  const char* image_name = NULL;
  size_t image_name_len = 0;
  if (!reader.ReadString(&image_name, &image_name_len))
    return false;

  // And then the command line for the variants that have it.
  const wchar_t* image_path = NULL;
  size_t image_path_len = 0;
  if (ProcessInfoTypeTraits<ProcessInfoType>::has_command_line &&
      !reader.ReadString(&image_path, &image_path_len))
    return false;

  process_info->process_id = info->ProcessId;
  process_info->parent_id = info->ParentId;
  process_info->session_id = info->SessionId;
  memcpy(&process_info->user_sid, sid, sid_len);
  process_info->image_name.assign(image_name, image_name_len);
  process_info->command_line.assign(image_path, image_path_len);

  *exit_status = info->ExitStatus;

  return true;
}

}  // namespace

bool KernelProcessEvents::ProcessInfo::operator == (
    const ProcessInfo& other) const {
  return process_id == other.process_id &&
      parent_id == other.parent_id &&
      session_id == other.session_id &&
      ::EqualSid(const_cast<SID*>(&user_sid),
                 const_cast<SID*>(&other.user_sid)) &&
      image_name == other.image_name &&
      command_line == other.command_line;
}

KernelLogParser::KernelLogParser() : module_event_sink_(NULL),
    process_event_sink_(NULL), infer_bitness_from_log_(true),
    is_64_bit_log_(false) {
}

KernelLogParser::~KernelLogParser() {
}

bool KernelLogParser::ProcessImageLoadEvent(EVENT_TRACE* event) {
  DCHECK(event && event->Header.Guid == kImageLoadEventClass);

  if (module_event_sink_ == NULL)
    return false;

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  KernelModuleEvents::ModuleInformation info = {};
  DWORD process_id = 0;

#define EVENT_HANDLER(type, version, event_type, handler) \
  if (event->Header.Class.Type == type && \
      event->Header.Class.Version == version) { \
    event_type* data = reinterpret_cast<event_type*>(event->MofData); \
    if (ConvertModuleInformationFromLogEvent(data, \
                                             event->MofLength, \
                                             &process_id, \
                                             &info)) { \
      if (process_id == 0) \
        process_id = event->Header.ProcessId; \
      module_event_sink_->handler(process_id, time, info); \
      return true; \
    } \
  }

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

#undef EVENT_HANDLER

  return false;
}

bool KernelLogParser::ProcessPageFaultEvent(EVENT_TRACE* event) {
  DCHECK(event && event->Header.Guid == kPageFaultEventClass);

  if (page_fault_event_sink_ == NULL)
    return false;

  if (event->Header.Class.Version != 0)
    return false;

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));

  if (event->Header.Class.Type == kHardPageFaultEvent) {
    if (event->MofLength < sizeof(HardPageFault32V0))
      return false;

    HardPageFault32V0* data =
        reinterpret_cast<HardPageFault32V0*>(event->MofData);

    // TODO(siggi): is this right?
    base::Time initial_time(base::Time::FromFileTime(
        reinterpret_cast<FILETIME&>(data->InitialTime)));

    page_fault_event_sink_->OnHardPageFault(
        event->Header.ProcessId, event->Header.ThreadId, time, initial_time,
        data->ReadOffset, data->VirtualAddress, data->FileObject,
        data->ThreadId, data->ByteCount);
    return true;
  } else {
    // TODO(siggi): fixme.
    NOTREACHED() << "Implementing non-hard faults not implemented yet.";
  }

  return false;
}

bool KernelLogParser::ProcessProcessEvent(EVENT_TRACE* event) {
  DCHECK(event && event->Header.Guid == kProcessEventClass);

  switch (event->Header.Class.Type) {
      case kProcessIsRunningEvent:
      case kProcessStartEvent:
      case kProcessEndEvent:
        // Add other known event types here.
        break;

    default:
      // Unknown event type.
      return false;
  }

  if (process_event_sink_ == NULL)
    return false;

  KernelProcessEvents::ProcessInfo process_info;
  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  bool has_info = false;
  ULONG exit_status = 0;

  if (is_64_bit_log_) {
    switch (event->Header.Class.Version) {
      case 0:
        NOTREACHED();  // TODO(siggi): writeme.
        break;
      case 1:
        NOTREACHED();  // TODO(siggi): writeme.
        break;
      case 2: {
          has_info =
              ParseProcessEvent<ProcessInfo64V2>(event->MofData,
                                                 event->MofLength,
                                                 &process_info,
                                                 &exit_status);
        }
        break;
      case 3: {
          has_info =
              ParseProcessEvent<ProcessInfo64V3>(event->MofData,
                                                 event->MofLength,
                                                 &process_info,
                                                 &exit_status);
        }
        break;

      default:
        LOG(ERROR) << "Unexpected process info version "
            << event->Header.Class.Version;
        break;
    }
  } else {
    switch (event->Header.Class.Version) {
      case 0:
        NOTREACHED();  // TODO(siggi): writeme.
        break;
      case 1: {
          has_info =
              ParseProcessEvent<ProcessInfo32V1>(event->MofData,
                                                 event->MofLength,
                                                 &process_info,
                                                 &exit_status);
        }
        break;
      case 2: {
          has_info =
              ParseProcessEvent<ProcessInfo32V2>(event->MofData,
                                                 event->MofLength,
                                                 &process_info,
                                                 &exit_status);
        }
        break;
      case 3: {
          has_info =
              ParseProcessEvent<ProcessInfo32V3>(event->MofData,
                                                 event->MofLength,
                                                 &process_info,
                                                 &exit_status);
        }
        break;

      default:
        LOG(ERROR) << "Unexpected process info version "
            << event->Header.Class.Version;
        break;
    }
  }

  if (has_info) {
    switch (event->Header.Class.Type) {
      case kProcessIsRunningEvent:
        process_event_sink_->OnProcessIsRunning(time, process_info);
        break;

      case kProcessStartEvent:
        process_event_sink_->OnProcessStarted(time, process_info);
        break;

      case kProcessEndEvent:
        process_event_sink_->OnProcessEnded(time, process_info, exit_status);
        break;
    }

    return true;
  }

  return false;
}

bool KernelLogParser::ProcessOneEvent(EVENT_TRACE* event) {
  if (event->Header.Guid == kImageLoadEventClass) {
    return ProcessImageLoadEvent(event);
  } else if (event->Header.Guid == kPageFaultEventClass) {
    return ProcessPageFaultEvent(event);
  } else if (event->Header.Guid == kProcessEventClass) {
    return ProcessProcessEvent(event);
  } else if (event->Header.Guid == kEventTraceEventClass) {
    if (event->Header.Class.Type == kLogFileHeaderEvent) {
      LogFileHeader32* data =
          reinterpret_cast<LogFileHeader32*>(event->MofData);

      if (infer_bitness_from_log_) {
        is_64_bit_log_ = (data->PointerSize == 8);
      }
    }
    return true;
  }

  return false;
}

KernelLogConsumer* KernelLogConsumer::current_ = NULL;

KernelLogConsumer::KernelLogConsumer() {
  DCHECK(current_ == NULL);
  current_ = this;
}

KernelLogConsumer::~KernelLogConsumer() {
  DCHECK(current_ == this);
  current_ = NULL;
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
