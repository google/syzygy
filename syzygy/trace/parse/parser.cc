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
// Implementation of call-trace parsing.

#include "syzygy/trace/parse/parser.h"

#include "base/logging.h"
#include "syzygy/common/buffer_parser.h"
#include "syzygy/trace/parse/parse_engine_rpc.h"

namespace trace {
namespace parser {

using ::common::BinaryBufferParser;

Parser::Parser() : active_parse_engine_(NULL) {
}

Parser::~Parser() {
  ignore_result(Close());

  ParseEngineIter it = parse_engine_set_.begin();
  for (; it != parse_engine_set_.end(); ++it) {
    delete *it;
  }
  parse_engine_set_.clear();
}

void Parser::AddParseEngine(ParseEngine* parse_engine) {
  DCHECK(parse_engine != NULL);
  parse_engine_set_.push_front(parse_engine);
}

bool Parser::Init(ParseEventHandler* event_handler) {
  DCHECK(event_handler != NULL);
  DCHECK(active_parse_engine_ == NULL);

  ParseEngine* engine = NULL;

  // Create the RPC call-trace parse engine.
  LOG(INFO) << "Initializing RPC call-trace parse engine.";
  engine = new ParseEngineRpc;
  if (engine == NULL) {
    LOG(ERROR) << "Failed to initialize RPC call-trace parse engine.";
    return false;
  }
  parse_engine_set_.push_back(engine);

  // Setup the event handler for all of the engines.
  ParseEngineIter it = parse_engine_set_.begin();
  for (; it != parse_engine_set_.end(); ++it) {
    (*it)->set_event_handler(event_handler);
  }

  return true;
}

bool Parser::error_occurred() const {
  DCHECK(active_parse_engine_ != NULL);
  return active_parse_engine_->error_occurred();
}

void Parser::set_error_occurred(bool value) {
  DCHECK(active_parse_engine_ != NULL);
  active_parse_engine_->set_error_occurred(value);
}

bool Parser::OpenTraceFile(const base::FilePath& trace_file_path) {
  DCHECK(!trace_file_path.empty());

  if (active_parse_engine_ == NULL && !SetActiveParseEngine(trace_file_path)) {
    return false;
  }

  DCHECK(active_parse_engine_ != NULL);
  return active_parse_engine_->OpenTraceFile(trace_file_path);
}

bool Parser::Consume() {
  if (active_parse_engine_ == NULL) {
    LOG(ERROR) << "No open trace files to consume.";
    return false;
  }
  return active_parse_engine_->ConsumeAllEvents();
}

const ModuleInformation* Parser::GetModuleInformation(
    uint32 process_id, AbsoluteAddress64 addr) const {
  DCHECK(active_parse_engine_ != NULL);
  return active_parse_engine_->GetModuleInformation(process_id, addr);
}

bool Parser::Close() {
  bool result = true;
  if (active_parse_engine_ != NULL) {
    result = active_parse_engine_->CloseAllTraceFiles();
    active_parse_engine_ = NULL;
  }
  return result;
}

bool Parser::SetActiveParseEngine(const base::FilePath& trace_file_path) {
  DCHECK(!trace_file_path.empty());
  DCHECK(active_parse_engine_ == NULL);

  ParseEngineIter it = parse_engine_set_.begin();
  for (; it != parse_engine_set_.end(); ++it) {
    ParseEngine* engine = *it;
    if (engine->IsRecognizedTraceFile(trace_file_path)) {
      LOG(INFO) << "Using " << engine->name() << " Call-Trace Parser.";
      active_parse_engine_ = engine;
      return true;
    }
  }

  LOG(ERROR) << "Failed to find a parse engine for \""
             << trace_file_path.value()
             << "\".";

  return false;
}

void ParseEventHandlerImpl::OnProcessStarted(base::Time time,
                                             DWORD process_id,
                                             const TraceSystemInfo* data) {
}

void ParseEventHandlerImpl::OnProcessEnded(base::Time time, DWORD process_id) {
}

void ParseEventHandlerImpl::OnFunctionEntry(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceEnterExitEventData* data) {
}

void ParseEventHandlerImpl::OnFunctionExit(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceEnterExitEventData* data) {
}

void ParseEventHandlerImpl::OnBatchFunctionEntry(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceBatchEnterData* data) {
}

void ParseEventHandlerImpl::OnProcessAttach(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceModuleData* data) {
}

void ParseEventHandlerImpl::OnProcessDetach(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceModuleData* data) {
}

void ParseEventHandlerImpl::OnThreadAttach(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceModuleData* data) {
}

void ParseEventHandlerImpl::OnThreadDetach(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceModuleData* data) {
}

void ParseEventHandlerImpl::OnInvocationBatch(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    size_t num_invocations,
    const TraceBatchInvocationInfo* data) {
}

void ParseEventHandlerImpl::OnThreadName(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const base::StringPiece& thread_name) {
}

void ParseEventHandlerImpl::OnIndexedFrequency(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceIndexedFrequencyData* data) {
}

void ParseEventHandlerImpl::OnDynamicSymbol(
    DWORD process_id, uint32 symbol_id, const base::StringPiece& symbol_name) {
}

void ParseEventHandlerImpl::OnSampleData(
    base::Time Time, DWORD process_id, const TraceSampleData* data) {
}

}  // namespace parser
}  // namespace trace
