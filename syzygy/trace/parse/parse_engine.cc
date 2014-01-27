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
// Base class for common trace parsing infrastructure.
#include "syzygy/trace/parse/parse_engine.h"

#include <windows.h>  // NOLINT
#include <wmistr.h>  // NOLINT
#include <evntrace.h>

#include "base/logging.h"
#include "syzygy/common/buffer_parser.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/trace/parse/parser.h"

namespace trace {
namespace parser {

using ::common::BinaryBufferReader;

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
  // conflicting information, so we ignore them.
  if (module_info.image_file_name.empty())
    return true;

  ModuleSpace& module_space = processes_[process_id];
  AbsoluteAddress64 addr(module_info.base_address);
  ModuleSpace::Range range(addr, module_info.module_size);

  AnnotatedModuleInformation new_module_info(module_info);

  ModuleSpace::RangeMapIter iter;
  if (module_space.FindOrInsert(range, new_module_info, &iter)) {
    return true;
  }

  // Perhaps this is a case of conflicting paths for the same module. We often
  // get paths reported to us in \Device\HarddiskVolumeN\... notation, and
  // othertimes in C:\... notation. In this case we're happy if everything
  // matches except the path. For a little bit of extra sanity checking we
  // also check the basename of the paths.
  if (module_info.base_address == iter->second.base_address &&
      module_info.image_checksum == iter->second.image_checksum &&
      module_info.module_size == iter->second.module_size &&
      module_info.time_date_stamp == iter->second.time_date_stamp) {
    base::FilePath path1(module_info.image_file_name);
    base::FilePath path2(iter->second.image_file_name);
    if (path1.BaseName() == path2.BaseName()) {
      return true;
    }
  }

  // Perhaps this is a case of process id reuse. In that case, we should have
  // previously seen a module unload event and marked the module information
  // as dirty.
  while (iter->second.is_dirty) {
    module_space.Remove(iter->first);
    if (module_space.FindOrInsert(range, new_module_info, &iter)) {
      return true;
    }
  }

  LOG(ERROR) << "Conflicting module info for pid=" << process_id << ": "
             << module_info.image_file_name
             << " (base=0x" << module_info.base_address
             << ", size=" << module_info.module_size << ") and "
             << iter->second.image_file_name
             << " (base=0x" << iter->second.base_address
             << ", size=" << iter->second.module_size << ").";

  return fail_on_module_conflict_ ? false : true;
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
    if (fail_on_module_conflict_)
      return false;
  }

  // We only remove modules from a given process if a conflicting module is
  // loaded after the module has been marked as dirty. This is because (1) we
  // don't guarantee temporal order of all events in a process, so you
  // might parse a function event after seeing the module get unloaded
  // if the buffers are flushed in that order; and (2) because process ids may
  // be reused (but not concurrently) so we do want to drop stale module info
  // when the process has been replaced.

  it->second.is_dirty = true;

  return true;
}

bool ParseEngine::RemoveProcessInformation(DWORD process_id) {
  ProcessMap::iterator proc_iter = processes_.find(process_id);
  if (proc_iter == processes_.end()) {
    LOG(ERROR) << "Unknown process id: " << process_id << ".";
    return false;
  }

  ModuleSpace& process_info = proc_iter->second;

  ModuleSpace::iterator module_iter = process_info.begin();
  for (; module_iter != process_info.end(); ++module_iter) {
    module_iter->second.is_dirty = true;
  }

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

    case TRACE_PROCESS_ENDED:
      success = DispatchProcessEndedEvent(event);
      break;

    case TRACE_MODULE_EVENT:
      LOG(ERROR) << "Parsing for TRACE_MODULE_EVENT not yet implemented.";
      break;

    case TRACE_BATCH_INVOCATION:
      success = DispatchBatchInvocationEvent(event);
      break;

    case TRACE_THREAD_NAME:
      success = DispatchThreadNameEvent(event);
      break;

    case TRACE_INDEXED_FREQUENCY:
      success = DispatchIndexedFrequencyEvent(event);
      break;

    case TRACE_DYNAMIC_SYMBOL:
      success = DispatchDynamicSymbolEvent(event);
      break;

    case TRACE_SAMPLE_DATA:
      success = DispatchSampleDataEvent(event);
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

  if (!reader.Read(sizeof(TraceEnterExitEventData), &data)) {
    LOG(ERROR) << "Short entry exit event.";
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
  size_t offset_to_calls = FIELD_OFFSET(TraceBatchEnterData, calls);
  if (!reader.Read(offset_to_calls, &data)) {
    LOG(ERROR) << "Short or empty batch event.";
    return false;
  }

  size_t bytes_needed = data->num_calls * sizeof(data->calls[0]);
  if (!reader.Consume(bytes_needed)) {
    LOG(ERROR) << "Short batch event data. Expected " << data->num_calls
               << " entries (" << (offset_to_calls + bytes_needed)
               << " bytes) but batch record was only " << event->MofLength
               << " bytes.";
    return false;
  }

  // Trim the batch entries if the last one is NULL, indicating that the
  // reporting thread was interrupted mid-write.
  if (data->num_calls != 0 &&
      data->calls[data->num_calls - 1].function == NULL) {
    // Yuck! Cast away constness because the BinaryBufferReader only likes
    // to deal with const output pointers.
    const_cast<TraceBatchEnterData*>(data)->num_calls -= 1;
  }
  DCHECK(data->num_calls == 0 ||
         data->calls[data->num_calls - 1].function != NULL);

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = data->thread_id;
  event_handler_->OnBatchFunctionEntry(time, process_id, thread_id, data);
  return true;
}

bool ParseEngine::DispatchProcessEndedEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));

  event_handler_->OnProcessEnded(time, event->Header.ProcessId);
  if (!RemoveProcessInformation(event->Header.ProcessId))
    return false;

  return true;
}

bool ParseEngine::DispatchBatchInvocationEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  if (event->MofLength % sizeof(InvocationInfo) != 0) {
    LOG(ERROR) << "Invocation batch length off.";
    return false;
  }

  const TraceBatchInvocationInfo* data = NULL;
  if (!reader.Read(event->MofLength, &data)) {
    LOG(ERROR) << "Short or empty batch event.";
    return false;
  }

  // TODO(rogerm): Ensure this is robust in the presence of incomplete write.
  size_t num_invocations = event->MofLength / sizeof(InvocationInfo);
  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = event->Header.ThreadId;
  event_handler_->OnInvocationBatch(time,
                                    process_id,
                                    thread_id,
                                    num_invocations,
                                    data);

  return true;
}

bool ParseEngine::DispatchThreadNameEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const char* thread_name = NULL;
  size_t thread_name_len = 0;
  if (!reader.ReadString(&thread_name, &thread_name_len)) {
    LOG(ERROR) << "Unable to read string.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = event->Header.ThreadId;
  event_handler_->OnThreadName(time,
                               process_id,
                               thread_id,
                               base::StringPiece(thread_name, thread_name_len));

  return true;
}

bool ParseEngine::DispatchIndexedFrequencyEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  if (event->MofLength < sizeof(TraceIndexedFrequencyData)) {
    LOG(ERROR) << "Data too small for TraceIndexedFrequency struct.";
    return false;
  }

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceIndexedFrequencyData* data = NULL;
  if (!reader.Read(&data)) {
    LOG(ERROR) << "Short or empty coverage data event.";
    return false;
  }
  DCHECK(data != NULL);

  // Calculate the expected size of the entire payload, headers included.
  size_t expected_length = data->frequency_size * data->num_entries +
      sizeof(TraceIndexedFrequencyData) - 1;
  if (event->MofLength < expected_length) {
    LOG(ERROR) << "Payload smaller than size implied by "
               << "TraceIndexedFrequencyData header.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  DWORD thread_id = event->Header.ThreadId;
  event_handler_->OnIndexedFrequency(time, process_id, thread_id, data);

  return true;
}

bool ParseEngine::DispatchDynamicSymbolEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceDynamicSymbol* symbol = NULL;
  const char* symbol_name = NULL;
  size_t symbol_name_len = 0;
  if (!reader.Read(FIELD_OFFSET(TraceDynamicSymbol, symbol_name), &symbol) ||
      !reader.ReadString(&symbol_name, &symbol_name_len)) {
    LOG(ERROR) << "Short or empty coverage data event.";
    return false;
  }

  DWORD process_id = event->Header.ProcessId;
  event_handler_->OnDynamicSymbol(
      process_id, symbol->symbol_id,
      base::StringPiece(symbol_name, symbol_name_len));

  return true;
}

bool ParseEngine::DispatchSampleDataEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);
  DCHECK(event_handler_ != NULL);
  DCHECK(error_occurred_ == false);

  BinaryBufferReader reader(event->MofData, event->MofLength);
  const TraceSampleData* data = NULL;
  if (!reader.Read(&data)) {
    LOG(ERROR) << "Short or empty TraceSampleData event.";
    return false;
  }
  DCHECK(data != NULL);

  // Calculate the expected size of the entire payload, headers included.
  size_t expected_length = FIELD_OFFSET(TraceSampleData, buckets) +
      sizeof(data->buckets[0]) * data->bucket_count;
  if (event->MofLength < expected_length) {
    LOG(ERROR) << "Payload smaller than size implied by TraceSampleData "
               << "header.";
    return false;
  }

  base::Time time(base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp)));
  DWORD process_id = event->Header.ProcessId;
  event_handler_->OnSampleData(time, process_id, data);

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

  if (data->module_base_addr == NULL) {
    LOG(INFO) << "Encountered incompletely written module event record.";
    return true;
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

}  // namespace parser
}  // namespace trace
