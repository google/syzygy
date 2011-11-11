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
// Base class for common trace parsing infrastructure.

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>

#include "base/logging.h"
#include "sawbuck/common/buffer_parser.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/call_trace/parse_engine.h"
#include "syzygy/call_trace/parser.h"

namespace call_trace {
namespace parser {

ParseEngine::ParseEngine(const char* name, bool fail_on_module_conflict)
    : event_handler_(NULL),
      error_occurred_(false),
      fail_on_module_conflict_(fail_on_module_conflict) {
  DCHECK(name != NULL);
  DCHECK(name[0] != '\0');
  name_ = name;
}

ParseEngine::~ParseEngine() {
}

const char* ParseEngine::name() const {
  return name_.c_str();
}

bool ParseEngine::error_occurred() const {
  return error_occurred_;
}

void ParseEngine::set_error_occurred(bool value) {
  error_occurred_ = value;
}

void ParseEngine::set_event_handler(ParseEventHandler* event_handler) {
  DCHECK(event_handler_ == NULL);
  DCHECK(event_handler != NULL);
  event_handler_ = event_handler;
}

const ModuleInformation* ParseEngine::GetModuleInformation(
    uint32 process_id, AbsoluteAddress64 addr) const {
  ProcessMap::const_iterator processes_it = processes_.find(process_id);
  if (processes_it == processes_.end())
    return NULL;

  const ModuleSpace& module_space = processes_it->second;
  ModuleSpace::Range range(addr, 1);
  ModuleSpace::RangeMapConstIter module_it =
      module_space.FindFirstIntersection(range);
  if (module_it == module_space.end())
    return NULL;

  return &module_it->second;
}

bool ParseEngine::AddModuleInformation(DWORD process_id,
                                       const ModuleInformation& module_info) {
    // Avoid doing needless work.
  if (module_info.module_size == 0)
    return true;

  // This happens in Windows XP ETW traces for some reason. They contain
  // conflicing information, so we ignore them.
  if (module_info.image_file_name.empty())
    return true;

  ModuleSpace& module_space = processes_[process_id];
  AbsoluteAddress64 addr(module_info.base_address);
  ModuleSpace::Range range(addr, module_info.module_size);
  ModuleSpace::RangeMapIter iter;
  if (!module_space.FindOrInsert(range, module_info, &iter) ||
      iter->second != module_info) {
    LOG(ERROR) << "Trying to insert conflicting module: "
               << module_info.image_file_name
               << " (base=0x" << module_info.base_address
               << ", size=" << module_info.module_size << ").";
    if (fail_on_module_conflict_)
      return false;
  }

  return true;
}

bool ParseEngine::RemoveModuleInformation(
    DWORD process_id, const ModuleInformation& module_info) {
  // Avoid doing needless work.
  if (module_info.module_size == 0)
    return true;

  // This happens in Windows XP traces for some reason. They contain conflicing
  // information, so we ignore them.
  if (module_info.image_file_name.empty())
    return true;

  ModuleSpace& module_space = processes_[process_id];
  AbsoluteAddress64 addr(module_info.base_address);
  ModuleSpace::Range range(addr, module_info.module_size);
  ModuleSpace::RangeMapIter it = module_space.FindFirstIntersection(range);
  if (it == module_space.end()) {
    // We occasionally see this, as certain modules fire off multiple Unload
    // events, so we don't log an error. I'm looking at you, logman.exe.
    return true;
  }
  if (it->first != range) {
    LOG(ERROR) << "Trying to remove module with mismatching range: "
               << module_info.image_file_name
               << " (base=0x" << module_info.base_address
               << ", size=" << module_info.module_size << ").";
    return false;
  }

  // TODO(rogerm): Unfortunately, we can't actually remove the module info
  //     because there may yet be unflushed events we haven't processed. We
  //     cross our fingers that another instrumented module won't be loaded
  //     into the address space the now unloaded module used to inhabit (which
  //     will trigger an error).

  return true;
}

bool ParseEngine::DispatchEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  if (kCallTraceEventClass != event->Header.Guid)
    return false;

  bool success = false;
  TraceEventType type = static_cast<TraceEventType>(event->Header.Class.Type);

  switch (type) {
    case TRACE_ENTER_EVENT:
    case TRACE_EXIT_EVENT:
      success = DispatchEntryExitEvent(event, type);
      break;

    case TRACE_BATCH_ENTER:
      success = DispatchBatchEnterEvent(event);
      break;

    case TRACE_PROCESS_ATTACH_EVENT:
    case TRACE_PROCESS_DETACH_EVENT:
    case TRACE_THREAD_ATTACH_EVENT:
    case TRACE_THREAD_DETACH_EVENT:
      success = DispatchModuleEvent(event, type);
      break;

    case TRACE_MODULE_EVENT:
      LOG(ERROR) << "Parsing for TRACE_MODULE_EVENT not yet implemented.";
      break;

    default:
      LOG(ERROR) << "Unknown event type encountered.";
      break;
  }

  if (!success) {
    error_occurred_ = true;
  }

  return true;
}

bool ParseEngine::DispatchEntryExitEvent(EVENT_TRACE* event,
                                         TraceEventType type) {
  DCHECK(event != NULL);
  DCHECK(type == TRACE_ENTER_EVENT || type == TRACE_EXIT_EVENT);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceEnterExitEventData* data = NULL;

  if (!reader.Read(FIELD_OFFSET(TraceEnterExitEventData, traces), &data)) {
    LOG(ERROR) << "Short event header.";
    return false;
  }

  if (!reader.Consume(data->num_traces * sizeof(data->traces[0]))) {
    LOG(ERROR) << "Short event tail.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = event->Header.ThreadId;

  switch (type) {
    case TRACE_ENTER_EVENT:
      event_handler_->OnFunctionEntry(time, process_id, thread_id, data);
      break;

    case TRACE_EXIT_EVENT:
      event_handler_->OnFunctionExit(time, process_id, thread_id, data);
      break;

    default:
      NOTREACHED() << "Impossible event type.";
      return false;
  }

  return true;
}

bool ParseEngine::DispatchBatchEnterEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceBatchEnterData* data = NULL;
  if (!reader.Read(FIELD_OFFSET(TraceBatchEnterData, calls), &data)) {
    LOG(ERROR) << "Short or empty batch event.";
    return false;
  }

  if (!reader.Consume(data->num_calls * sizeof(data->calls[0]))) {
    LOG(ERROR) << "Short batch event data.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = data->thread_id;
  event_handler_->OnBatchFunctionEntry(time, process_id, thread_id, data);

  return true;
}

namespace {

ModuleInformation ModuleTraceDataToModuleInformation(
    const TraceModuleData& module_data) {
  ModuleInformation module_info = {};
  module_info.base_address =
      reinterpret_cast<uint32>(module_data.module_base_addr);
  module_info.module_size = module_data.module_base_size;
  module_info.image_file_name = module_data.module_name;
  module_info.image_checksum = module_data.module_checksum;
  module_info.time_date_stamp = module_data.module_time_date_stamp;
  return module_info;
}

}  // namespace

bool ParseEngine::DispatchModuleEvent(EVENT_TRACE* event,
                                      TraceEventType type) {
  DCHECK(event != NULL);
  DCHECK(type == TRACE_PROCESS_ATTACH_EVENT ||
         type == TRACE_PROCESS_DETACH_EVENT ||
         type == TRACE_THREAD_ATTACH_EVENT ||
         type == TRACE_THREAD_DETACH_EVENT);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceModuleData* data = NULL;
  if (!reader.Read(&data)) {
    LOG(ERROR) << "Short or empty module event.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = event->Header.ThreadId;

  switch (type) {
    case TRACE_PROCESS_ATTACH_EVENT:
      AddModuleInformation(process_id,
                           ModuleTraceDataToModuleInformation(*data));
      event_handler_->OnProcessAttach(time, process_id, thread_id, data);
      break;

    case TRACE_PROCESS_DETACH_EVENT:
      event_handler_->OnProcessDetach(time, process_id, thread_id, data);
      RemoveModuleInformation(process_id,
                              ModuleTraceDataToModuleInformation(*data));
      break;

    case TRACE_THREAD_ATTACH_EVENT:
      event_handler_->OnThreadAttach(time, process_id, thread_id, data);
      break;

    case TRACE_THREAD_DETACH_EVENT:
      event_handler_->OnThreadDetach(time, process_id, thread_id, data);
      break;

    default:
      LOG(ERROR) << "Unexpected module event type " << type << ".";
      return false;
  }

  return true;
}

}  // namespace call_trace::parser
}  // namespace call_trace
