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

#include "syzygy/agent/memprof/function_call_logger.h"

#include "syzygy/agent/common/stack_capture.h"

namespace agent {
namespace memprof {

FunctionCallLogger::FunctionCallLogger(
    trace::client::RpcSession* session,
    trace::client::TraceFileSegment* segment)
    : session_(session),
      segment_(segment),
      stack_trace_tracking_(kTrackingNone) {
  DCHECK_NE(static_cast<trace::client::RpcSession*>(nullptr), session);
  DCHECK_NE(static_cast<trace::client::TraceFileSegment*>(nullptr), segment);
}

// Given a function name returns it's ID. If this is the first time seeing
// a given function name then emits a record to the call-trace buffer.
uint32 FunctionCallLogger::GetFunctionId(const std::string& function_name) {
  size_t id = 0;

  {
    base::AutoLock lock(lock_);
    auto it = function_id_map_.find(function_name);
    if (it != function_id_map_.end())
      return it->second;
    id = function_id_map_.size();
    function_id_map_.insert(std::make_pair(function_name, id));
  }

  size_t data_size = FIELD_OFFSET(TraceFunctionNameTableEntry, name) +
      function_name.size() + 1;

  if (!segment_->CanAllocate(data_size) && !FlushSegment())
    return id;
  DCHECK(segment_->CanAllocate(data_size));

  TraceFunctionNameTableEntry* data =
      segment_->AllocateTraceRecord<TraceFunctionNameTableEntry>(data_size);
  DCHECK_NE(static_cast<TraceFunctionNameTableEntry*>(nullptr), data);
  data->function_id = id;
  data->name_length = function_name.size() + 1;
  ::memcpy(data->name, function_name.data(), data->name_length);

  return id;
}

uint32 FunctionCallLogger::GetStackTraceId() {
  if (stack_trace_tracking_ == kTrackingNone)
    return 0;

  agent::common::StackCapture stack;
  stack.InitFromStack();
  if (stack_trace_tracking_ == kTrackingTrack)
    return stack.stack_id();

  // Insert the stack ID. If it already exists it doesn't need to be emitted
  // so return early.
  bool inserted = false;
  {
    base::AutoLock lock(lock_);
    inserted = emitted_stack_ids_.insert(stack.stack_id()).second;
  }
  if (!inserted)
    return stack.stack_id();

  size_t frame_size = sizeof(void*) * stack.num_frames();
  size_t data_size = FIELD_OFFSET(TraceStackTrace, frames) + frame_size;
  if (!segment_->CanAllocate(data_size) && !FlushSegment())
    return stack.stack_id();
  DCHECK(segment_->CanAllocate(data_size));

  TraceStackTrace* data = segment_->AllocateTraceRecord<TraceStackTrace>(
      data_size);
  DCHECK_NE(static_cast<TraceStackTrace*>(nullptr), data);
  data->num_frames = stack.num_frames();
  data->stack_trace_id = stack.stack_id();
  ::memcpy(data->frames, stack.frames(), frame_size);

  return stack.stack_id();
}

bool FunctionCallLogger::FlushSegment() {
  return session_->ExchangeBuffer(segment_);
}

}  // namespace memprof
}  // namespace agent
