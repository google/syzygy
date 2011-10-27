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
// Implementation of RPC call-trace parsing.

#include "syzygy/call_trace/parse_engine_etw.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "sawbuck/common/buffer_parser.h"
#include "sawbuck/common/com_utils.h"

namespace call_trace {
namespace parser {

ParseEngineEtw* ParseEngineEtw::parse_engine_etw_ = NULL;

ParseEngineEtw::ParseEngineEtw() : ParseEngine("ETW") {
  DCHECK(parse_engine_etw_ == NULL);
  parse_engine_etw_ = this;
  kernel_log_parser_.set_module_event_sink(this);
  kernel_log_parser_.set_process_event_sink(this);
}

ParseEngineEtw::~ParseEngineEtw() {
  DCHECK(parse_engine_etw_ == this);
  parse_engine_etw_ = NULL;
}

bool ParseEngineEtw::IsRecognizedTraceFile(const FilePath& trace_file_path) {
  // TODO(rogerm): Figure out enough about the format of .ETL files to put a
  //     real test here. For now, we just rely on the check for ETW trace files
  //     being the last one in the Parser facade (to give all the other parsers
  //     a change to recognize their own files first) and fall back to failing
  //     in OpenTraceFile() if the the file turns out to be invalid.
  return true;
}

bool ParseEngineEtw::OpenTraceFile(const FilePath& trace_file_path) {
  HRESULT result =
      EtwConsumerBase::OpenFileSession(trace_file_path.value().c_str());

  if (result != S_OK) {
    LOG(ERROR) << "Failed to open ETW file session '"
               << trace_file_path.value() << "': " << com::LogHr(result)
               << ".";
    return false;
  }

  return true;
}

bool ParseEngineEtw::CloseAllTraceFiles() {
  HRESULT result = EtwConsumerBase::Close();
  if (result != S_OK) {
    LOG(ERROR) << "Failed to close all open ETW trace sessions: "
               << com::LogHr(result) << ".";
    return false;
  }

  return true;
}

bool ParseEngineEtw::ConsumeAllEvents() {
  HRESULT result = EtwConsumerBase::Consume();
  if (result != S_OK) {
    LOG(ERROR) << "Failed to consume ETW events stream: "
               << com::LogHr(result) << ".";
    return false;
  }

  return !error_occurred_;
}

// KernelModuleEvents implementation.
void ParseEngineEtw::OnModuleIsLoaded(DWORD process_id,
                                      const base::Time& time,
                                      const ModuleInformation& module_info) {
  // Simply forward this to OnModuleLoad.
  OnModuleLoad(process_id, time, module_info);
}

void ParseEngineEtw::OnModuleUnload(DWORD process_id,
                                    const base::Time& time,
                                    const ModuleInformation& module_info) {
  DCHECK(error_occurred_ == false);

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    error_occurred_ = true;
    return;
  }

  if (!RemoveModuleInformation(process_id, module_info)) {
    LOG(ERROR) << "Failed to unregister module.";
    error_occurred_ = true;
    return;
  }

  last_event_time_ = time;
}

void ParseEngineEtw::OnModuleLoad(DWORD process_id,
                                  const base::Time& time,
                                  const ModuleInformation& module_info) {
  DCHECK(error_occurred_ == false);

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    error_occurred_ = true;
    return;
  }

  if (!AddModuleInformation(process_id, module_info)) {
    LOG(ERROR) << "Failed to register module.";
    error_occurred_ = true;
    return;
  }

  last_event_time_ = time;
}

// KernelProcessEvents implementation.
void ParseEngineEtw::OnProcessIsRunning(const base::Time& time,
                                        const ProcessInfo& process_info) {
  DCHECK(error_occurred_ == false);

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    error_occurred_ = true;
    return;
  }

  // We don't care about these events.
}

void ParseEngineEtw::OnProcessStarted(const base::Time& time,
                                      const ProcessInfo& process_info) {
  DCHECK(error_occurred_ == false);

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    error_occurred_ = true;
    return;
  }

  // We don't care about these events.
}

void ParseEngineEtw::OnProcessEnded(const base::Time& time,
                                    const ProcessInfo& process_info,
                                    ULONG exit_status) {
  DCHECK(error_occurred_ == false);

  if (last_event_time_ > time) {
    LOG(ERROR) << "Messages out of temporal order.";
    error_occurred_ = true;
    return;
  }

  DCHECK(event_handler_ != NULL);
  event_handler_->OnProcessEnded(time, process_info.process_id);
}

void ParseEngineEtw::ProcessEvent(PEVENT_TRACE event) {
  DCHECK(event != NULL);
  DCHECK(parse_engine_etw_ != NULL);

  if (parse_engine_etw_->error_occurred_)
    return;

  // If the event is a call-trace event (i.e., no translation necessary) then
  // it can be handled by the base DispatchEvent() handler. Otherwise, the
  // dispatcher will return false. Note that in this case false means not
  // handled, not "an error occurred".
  if (parse_engine_etw_->DispatchEvent(event))
    return;

  DCHECK(parse_engine_etw_->error_occurred_ == false);

  // It's probably a kernel event, let's handle those by translating
  // them into the appropriate event type for Dispatch().
  parse_engine_etw_->kernel_log_parser_.ProcessOneEvent(event);
}

bool ParseEngineEtw::ProcessBuffer(PEVENT_TRACE_LOGFILE buffer) {
  DCHECK(buffer != NULL);
  DCHECK(parse_engine_etw_ != NULL);

  // If our consumer is errored, we bail early.
  return (!parse_engine_etw_->error_occurred_);
}

}  // namespace call_trace::parser
}  // namespace call_trace
