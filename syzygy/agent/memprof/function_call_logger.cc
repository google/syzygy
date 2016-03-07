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
    trace::client::RpcSession* session)
    : session_(session),
      stack_trace_tracking_(kTrackingNone),
      serialize_timestamps_(false),
      call_counter_(0),
      serial_(0) {
  DCHECK_NE(static_cast<trace::client::RpcSession*>(nullptr), session);

  // Generate a unique 'serial number' for this instance. This is so that we
  // can tell one logger from the next in unittests, where they often end up
  // having the same address.
  uint64_t t = ::trace::common::GetTsc();
  serial_ = static_cast<uint32_t>(t & 0xFFFFFFFF) ^
            static_cast<uint32_t>((t >> 32) & 0xFFFFFFFF) ^
            reinterpret_cast<uint32_t>(this);
}

// Given a function name returns it's ID. If this is the first time seeing
// a given function name then emits a record to the call-trace buffer.
uint32_t FunctionCallLogger::GetFunctionId(TraceFileSegment* segment,
                                           const std::string& function_name) {
  DCHECK_NE(static_cast<TraceFileSegment*>(nullptr), segment);
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

  if (!segment->CanAllocate(data_size) && !FlushSegment(segment))
    return id;
  DCHECK(segment->CanAllocate(data_size));

  TraceFunctionNameTableEntry* data =
      segment->AllocateTraceRecord<TraceFunctionNameTableEntry>(data_size);
  DCHECK_NE(static_cast<TraceFunctionNameTableEntry*>(nullptr), data);
  data->function_id = id;
  data->name_length = function_name.size() + 1;
  ::memcpy(data->name, function_name.data(), data->name_length);

  return id;
}

uint32_t FunctionCallLogger::GetStackTraceId(TraceFileSegment* segment) {
  DCHECK_NE(static_cast<TraceFileSegment*>(nullptr), segment);
  if (stack_trace_tracking_ == kTrackingNone)
    return 0;

  agent::common::StackCapture stack;
  stack.InitFromStack();
  if (stack_trace_tracking_ == kTrackingTrack)
    return stack.absolute_stack_id();

  // Insert the stack ID. If it already exists it doesn't need to be emitted
  // so return early.
  bool inserted = false;
  {
    base::AutoLock lock(lock_);
    inserted = emitted_stack_ids_.insert(stack.absolute_stack_id()).second;
  }
  if (!inserted)
    return stack.absolute_stack_id();

  size_t frame_size = sizeof(void*) * stack.num_frames();
  size_t data_size = FIELD_OFFSET(TraceStackTrace, frames) + frame_size;
  if (!segment->CanAllocate(data_size) && !FlushSegment(segment))
    return stack.absolute_stack_id();
  DCHECK(segment->CanAllocate(data_size));

  TraceStackTrace* data = segment->AllocateTraceRecord<TraceStackTrace>(
      data_size);
  DCHECK_NE(static_cast<TraceStackTrace*>(nullptr), data);
  data->num_frames = stack.num_frames();
  data->stack_trace_id = stack.absolute_stack_id();
  ::memcpy(data->frames, stack.frames(), frame_size);

  return stack.absolute_stack_id();
}

bool FunctionCallLogger::FlushSegment(TraceFileSegment* segment) {
  DCHECK_NE(static_cast<TraceFileSegment*>(nullptr), segment);
  return session_->ExchangeBuffer(segment);
}

}  // namespace memprof
}  // namespace agent
