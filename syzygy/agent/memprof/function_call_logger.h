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
//
// Declares a FunctionCallLogger class. This contains functionality for
// logging detailed function call records via the call-trace service.

#ifndef SYZYGY_AGENT_MEMPROF_FUNCTION_CALL_LOGGER_H_
#define SYZYGY_AGENT_MEMPROF_FUNCTION_CALL_LOGGER_H_

#include <set>

#include "syzygy/agent/memprof/parameters.h"
#include "syzygy/trace/client/rpc_session.h"

namespace agent {
namespace memprof {

class FunctionCallLogger {
 public:
  // Forward declarations.
  struct NoArgument;
  template<typename ArgType> struct ArgumentSerializer;

  typedef trace::client::TraceFileSegment TraceFileSegment;

  // Consructor.
  // @param session The call-trace session to log to.
  // @param segment The segment to write to.
  explicit FunctionCallLogger(trace::client::RpcSession* session);

  // Given a function name returns it's ID. If this is the first time seeing
  // a given function name then emits a record to the call-trace buffer.
  // @param function_name The name of the function.
  // @returns the ID of the function.
  uint32_t GetFunctionId(TraceFileSegment* segment,
                         const std::string& function_name);

  // Gets a stack ID for the current stack. The behaviour of this function
  // depends on the stack_trace_tracking mode. If disabled, this always
  // returns 0. If enabled, this returns the actual ID of the current stack.
  // If 'emit' mode is enabled, this will also keep track of already emitted
  // stack IDs and emit the stack the first time it's encountered.
  // @returns the ID of the current stack trace.
  uint32_t GetStackTraceId(TraceFileSegment* segment);

  // Emits a detailed function call event with a variable number of arguments.
  // @tparam ArgTypeN The type of the optional Nth argument.
  // @param function_id The ID of the function that was called.
  // @param stack_trace_id The ID of the stack trace where the function was
  //     called.
  // @param argN The value of the optional Nth argument.
  template <typename ArgType0 = NoArgument,
            typename ArgType1 = NoArgument,
            typename ArgType2 = NoArgument,
            typename ArgType3 = NoArgument,
            typename ArgType4 = NoArgument,
            typename ArgType5 = NoArgument>
  void EmitDetailedFunctionCall(TraceFileSegment* segment,
                                uint32_t function_id,
                                uint32_t stack_trace_id,
                                ArgType0 arg0 = NoArgument(),
                                ArgType1 arg1 = NoArgument(),
                                ArgType2 arg2 = NoArgument(),
                                ArgType3 arg3 = NoArgument(),
                                ArgType4 arg4 = NoArgument(),
                                ArgType5 arg5 = NoArgument());

  // @name Accessors and mutators.
  // @{
  StackTraceTracking stack_trace_tracking() const {
    return stack_trace_tracking_;
  }
  void set_stack_trace_tracking(StackTraceTracking tracking) {
    stack_trace_tracking_ = tracking;
  }
  bool serialize_timestamps() const {
    return serialize_timestamps_;
  }
  void set_serialize_timestamps(bool serialize_timestamps) {
    serialize_timestamps_ = serialize_timestamps;
  }
  // @}

  // @returns a unique serial number for this function call logger.
  // @note This is for unittesting purposes.
  uint32_t serial() const { return serial_; }

 protected:
  // Flushes the provided segment, and gets a new one.
  bool FlushSegment(TraceFileSegment* segment);

  // The stack-trace tracking mode. Default to kTrackingNone.
  StackTraceTracking stack_trace_tracking_;

  // Whether or not timestamps are being serialized.
  bool serialize_timestamps_;

  // The RPC session events are being written to.
  trace::client::RpcSession* session_;

  // A lock that is used for synchronizing access to internals.
  base::Lock lock_;

  // The counter to use for serialized timestamps. Only used if
  // |serialized_timestamps_| is true.
  uint64_t call_counter_;  // Under lock_.

  // A map of known function names and their IDs. This is used for making the
  // call-trace format more compact.
  typedef std::map<std::string, uint32_t> FunctionIdMap;
  FunctionIdMap function_id_map_;  // Under lock_.

  // A set of stack traces whose IDs have already been emitted. This is only
  // maintained if stack_trace_tracking_ is set to 'kTrackingEmit'.
  typedef std::set<uint32_t> StackIdSet;
  StackIdSet emitted_stack_ids_;  // Under lock_.

  // A unique serial number generated at construction time. For unittesting.
  uint32_t serial_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FunctionCallLogger);
};

// Used to indicate the lack of an argument in the detailed
// function call reporting helper.
struct FunctionCallLogger::NoArgument {};

// Helper for serializing argument contents.
template<typename ArgType>
struct FunctionCallLogger::ArgumentSerializer {
  size_t size() const {
    return sizeof(ArgType);
  }
  void serialize(ArgType argument, uint8_t* buffer) {
    ::memcpy(buffer, &argument, sizeof(ArgType));
  }
};

// A no-op serializer for unused arguments.
template<> struct FunctionCallLogger::ArgumentSerializer<
    FunctionCallLogger::NoArgument> {
  size_t size() const {
    return 0;
  }
  void serialize(NoArgument argument, uint8_t* buffer) { return; }
};

// Implementation off the detailed function call logger. Populates a
// TraceDetailedFunctionCall buffer with variable length encodings of
// the arguments. Arguments are serialized using the ArgumentSerializer
// helper.
template <typename ArgType0,
          typename ArgType1,
          typename ArgType2,
          typename ArgType3,
          typename ArgType4,
          typename ArgType5>
void FunctionCallLogger::EmitDetailedFunctionCall(TraceFileSegment* segment,
                                                  uint32_t function_id,
                                                  uint32_t stack_trace_id,
                                                  ArgType0 arg0,
                                                  ArgType1 arg1,
                                                  ArgType2 arg2,
                                                  ArgType3 arg3,
                                                  ArgType4 arg4,
                                                  ArgType5 arg5) {
  DCHECK_NE(static_cast<TraceFileSegment*>(nullptr), segment);
  size_t args_count = 0;
  size_t args_size = 0;

  size_t arg_size0 = ArgumentSerializer<ArgType0>().size();
  args_count += arg_size0 > 0 ? 1 : 0;
  args_size += arg_size0;

  size_t arg_size1 = ArgumentSerializer<ArgType1>().size();
  args_count += arg_size1 > 0 ? 1 : 0;
  args_size += arg_size1;

  size_t arg_size2 = ArgumentSerializer<ArgType2>().size();
  args_count += arg_size2 > 0 ? 1 : 0;
  args_size += arg_size2;

  size_t arg_size3 = ArgumentSerializer<ArgType3>().size();
  args_count += arg_size3 > 0 ? 1 : 0;
  args_size += arg_size3;

  size_t arg_size4 = ArgumentSerializer<ArgType4>().size();
  args_count += arg_size4 > 0 ? 1 : 0;
  args_size += arg_size4;

  size_t arg_size5 = ArgumentSerializer<ArgType5>().size();
  args_count += arg_size5 > 0 ? 1 : 0;
  args_size += arg_size5;

  if (args_size > 0)
    args_size += (args_count + 1) * sizeof(uint32_t);
  size_t data_size = FIELD_OFFSET(TraceDetailedFunctionCall, argument_data) +
      args_size;

  if (!segment->CanAllocate(data_size) && !FlushSegment(segment))
    return;
  DCHECK(segment->CanAllocate(data_size));

  TraceDetailedFunctionCall* data =
      segment->AllocateTraceRecord<TraceDetailedFunctionCall>(data_size);
  data->function_id = function_id;
  data->stack_trace_id = stack_trace_id;
  data->argument_data_size = args_size;

  if (serialize_timestamps_) {
    base::AutoLock lock(lock_);
    data->timestamp = call_counter_;
    ++call_counter_;
  } else {
    data->timestamp = ::trace::common::GetTsc();
  }

  if (args_size == 0)
    return;

  // Output the number of arguments.
  uint32_t* arg_sizes = reinterpret_cast<uint32_t*>(data->argument_data);
  *(arg_sizes++) = args_count;

  // Output argument sizes.
  if (arg_size0 > 0)
    *(arg_sizes++) = arg_size0;
  if (arg_size1 > 0)
    *(arg_sizes++) = arg_size1;
  if (arg_size2 > 0)
    *(arg_sizes++) = arg_size2;
  if (arg_size3 > 0)
    *(arg_sizes++) = arg_size3;
  if (arg_size4 > 0)
    *(arg_sizes++) = arg_size4;
  if (arg_size5 > 0)
    *(arg_sizes++) = arg_size5;

  // Output argument data.
  uint8_t* arg_data = reinterpret_cast<uint8_t*>(arg_sizes);
  ArgumentSerializer<ArgType0>().serialize(arg0, arg_data);
  arg_data += arg_size0;
  ArgumentSerializer<ArgType1>().serialize(arg1, arg_data);
  arg_data += arg_size1;
  ArgumentSerializer<ArgType2>().serialize(arg2, arg_data);
  arg_data += arg_size2;
  ArgumentSerializer<ArgType3>().serialize(arg3, arg_data);
  arg_data += arg_size3;
  ArgumentSerializer<ArgType4>().serialize(arg4, arg_data);
  arg_data += arg_size4;
  ArgumentSerializer<ArgType5>().serialize(arg5, arg_data);
  arg_data += arg_size5;
}

// A templated helper for emitting a detailed function call record.
// @param function_call_logger A pointer to the function call logger
//     instance to use.
// @param segment A pointer to the TraceFileSegment to write to.
// @param logger_serial A pointer to where the serial number of the previous
//     function call logger can be stored. Must be statically initialized to
//     -1.
// @param function_id A pointer where the function ID can be saved. Must
//     be statically initialized to -1.
// @param function_name The name of the function being traced.
// @param arguments The arguments to the function being traced.
template <typename... Arguments>
inline void EmitDetailedFunctionCallHelper(
    FunctionCallLogger* function_call_logger,
    trace::client::TraceFileSegment* segment,
    uint32_t* logger_serial,
    uint32_t* function_id,
    const char* function_name,
    const Arguments&... arguments) {
  DCHECK_NE(static_cast<FunctionCallLogger*>(nullptr), function_call_logger);
  DCHECK_NE(static_cast<trace::client::TraceFileSegment*>(nullptr), segment);
  DCHECK_NE(static_cast<uint32_t*>(nullptr), logger_serial);
  DCHECK_NE(static_cast<uint32_t*>(nullptr), function_id);
  DCHECK_NE(static_cast<char*>(nullptr), function_name);

  // This is racy but safe because of the way GetFunctionId works and because
  // 32-bit writes are atomic.
  if (*logger_serial != function_call_logger->serial() ||
      *function_id == -1) {
    *logger_serial = function_call_logger->serial();
    *function_id = function_call_logger->GetFunctionId(segment, function_name);
  }
  uint32_t stack_trace_id = function_call_logger->GetStackTraceId(segment);
  function_call_logger->EmitDetailedFunctionCall(
      segment, *function_id, stack_trace_id, arguments...);
}

// A macro for emitting a detailed function call record. Automatically
// emits a function name record the first time it is invoked for a given
// function. This is a macro because it needs to use some function scope
// static storage.
// @param function_call_logger A pointer to the function call logger
//     instance to use.
// @param segment A pointer to the TraceFileSegment to write to.
#define EMIT_DETAILED_FUNCTION_CALL(function_call_logger, segment, ...)        \
  {                                                                            \
    static uint32_t logger_serial = UINT32_MAX;                                \
    static uint32_t function_id = UINT32_MAX;                                  \
    EmitDetailedFunctionCallHelper((function_call_logger), (segment),          \
                                   &logger_serial, &function_id, __FUNCTION__, \
                                   __VA_ARGS__);                               \
  }

}  // namespace memprof
}  // namespace agent

#endif  // SYZYGY_AGENT_MEMPROF_FUNCTION_CALL_LOGGER_H_
