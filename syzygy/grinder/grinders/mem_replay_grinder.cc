// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/grinder/grinders/mem_replay_grinder.h"

#include <cstring>

#include "syzygy/bard/raw_argument_converter.h"
#include "syzygy/bard/events/get_process_heap_event.h"
#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_realloc_event.h"
#include "syzygy/bard/events/heap_set_information_event.h"
#include "syzygy/bard/events/heap_size_event.h"

namespace grinder {
namespace grinders {

namespace {

const char* kAsanHeapFunctionNames[] = {
    "asan_GetProcessHeap",
    "asan_HeapAlloc",
    "asan_HeapCreate",
    "asan_HeapDestroy",
    "asan_HeapFree",
    "asan_HeapReAlloc",
    "asan_HeapSetInformation",
    "asan_HeapSize",
};

using RawArgumentConverters = std::vector<bard::RawArgumentConverter>;

// A templated utility function for parsing a value from a buffer by copying
// its contents.
bool ParseUint32(const uint8* end, const uint8** cursor, uint32* value) {
  DCHECK_NE(static_cast<uint8*>(nullptr), end);
  DCHECK_NE(static_cast<uint8**>(nullptr), cursor);
  DCHECK_NE(static_cast<uint8*>(nullptr), *cursor);
  DCHECK_LE(*cursor, end);
  DCHECK_NE(static_cast<uint32*>(nullptr), value);

  if (std::distance(*cursor, end) < sizeof(*value))
    return false;
  *value = *reinterpret_cast<const uint32*>(*cursor);
  *cursor += sizeof(*value);
  return true;
}

// Builds a vector of RawArgumentConverter objects on top of the stored
// arguments in the provided TraceDetailedFunctionCall.
bool BuildArgumentConverters(const TraceDetailedFunctionCall* data,
                             RawArgumentConverters* converters) {
  DCHECK_NE(static_cast<TraceDetailedFunctionCall*>(nullptr), data);
  DCHECK_NE(static_cast<RawArgumentConverters*>(nullptr), converters);
  const uint8_t* cursor = data->argument_data;
  const uint8_t* end = data->argument_data + data->argument_data_size;

  // Parse the size of the argument list present in the
  // TraceDetailedFunctionCall record. See the encoding documented in
  // function_call_logger.h.
  uint32_t arg_count = 0;
  if (!ParseUint32(end, &cursor, &arg_count))
    return false;

  converters->clear();
  converters->reserve(arg_count);

  // Parse the argument sizes and contents themselves.
  const uint8_t* arg_data = cursor + sizeof(uint32_t) * arg_count;
  for (size_t i = 0; i < arg_count; ++i) {
    uint32_t arg_size = 0;
    if (!ParseUint32(end, &cursor, &arg_size))
      return false;

    if (arg_data + arg_size > end)
      return false;
    converters->push_back(bard::RawArgumentConverter(arg_data, arg_size));
    arg_data += arg_size;
  }

  return true;
}

// Helper class for ArgumentParser.
template <typename T>
struct ArgumentParserTraits {
  static const size_t kCount = 1;
};

// Dummy type for ArgumentParser.
struct ArgumentParserDummy {};

// Specialization of dummy type for ArgumentParser.
template <>
struct ArgumentParserTraits<ArgumentParserDummy> {
  static const size_t kCount = 0;
};

// Helper class for parsing and validating arguments. The argument are provided
// as an array of RawArgumentConverters which implicitly check for
// size-compatibility with the output argument types. Allows for very compact
// parsing of DetailedFunctionCalls using code like the following:
//
//   // Extract the encoded arguments to a vector of converters.
//   RawArgumentConverters args;
//   CHECK(BuildArgumentConverters(detailed_function_call, &args));
//   // And parse them to their final types. Argument count and size
//   // constraints are automatically enforced here.
//   ArgumentParser<Foo, Bar> arg_parser;
//   CHECK(arg_parser.Parse(args));
//   Foo foo = arg_parser.arg0();
//   Bar bar = arg_parser.arg1();
template <typename T0,
          typename T1 = ArgumentParserDummy,
          typename T2 = ArgumentParserDummy,
          typename T3 = ArgumentParserDummy,
          typename T4 = ArgumentParserDummy,
          typename T5 = ArgumentParserDummy,
          typename T6 = ArgumentParserDummy>
class ArgumentParser {
 public:
  static const size_t kCount =
      ArgumentParserTraits<T0>::kCount + ArgumentParserTraits<T1>::kCount +
      ArgumentParserTraits<T2>::kCount + ArgumentParserTraits<T3>::kCount +
      ArgumentParserTraits<T4>::kCount + ArgumentParserTraits<T5>::kCount +
      ArgumentParserTraits<T6>::kCount;

  // Parses the arguments from the provided converter. Returns true on success,
  // false otherwise.
  bool Parse(const RawArgumentConverters& args) {
    if (args.size() != kCount)
      return false;
    static_assert(kCount <= 7, "need to update this switch");
    switch (kCount) {
      // These case statements deliberately fall through.
      case 7:
        if (!args[6].RetrieveAs(&arg6_))
          return false;
      case 6:
        if (!args[5].RetrieveAs(&arg5_))
          return false;
      case 5:
        if (!args[4].RetrieveAs(&arg4_))
          return false;
      case 4:
        if (!args[3].RetrieveAs(&arg3_))
          return false;
      case 3:
        if (!args[2].RetrieveAs(&arg2_))
          return false;
      case 2:
        if (!args[1].RetrieveAs(&arg1_))
          return false;
      case 1:
        if (!args[0].RetrieveAs(&arg0_))
          return false;
    }
    return true;
  }

  const T0& arg0() const { return arg0_; }
  const T1& arg1() const { return arg1_; }
  const T2& arg2() const { return arg2_; }
  const T3& arg3() const { return arg3_; }
  const T4& arg4() const { return arg4_; }
  const T5& arg5() const { return arg5_; }
  const T6& arg6() const { return arg6_; }

 private:
  T0 arg0_;
  T1 arg1_;
  T2 arg2_;
  T3 arg3_;
  T4 arg4_;
  T5 arg5_;
  T6 arg6_;
};

}  // namespace

MemReplayGrinder::MemReplayGrinder() : parse_error_(false) {
}

bool MemReplayGrinder::ParseCommandLine(
    const base::CommandLine* command_line) {
  DCHECK_NE(static_cast<base::CommandLine*>(nullptr), command_line);
  LoadAsanFunctionNames();

  return true;
}

void MemReplayGrinder::SetParser(Parser* parser) {
  DCHECK_NE(static_cast<Parser*>(nullptr), parser);
  // This grinder doesn't actually care about the parser in use.
}

bool MemReplayGrinder::Grind() {
  if (parse_error_) {
    LOG(ERROR) << "Encountered an error during parsing.";
    return false;
  }

  for (auto& proc_id_data_pair : process_data_map_) {
    auto& proc_data = proc_id_data_pair.second;
    if (!proc_data.pending_function_ids.empty() ||
        !proc_data.pending_calls.empty()) {
      LOG(ERROR) << "The trace file function name table is incomplete and not "
                 << "all detailed function call records could be parsed.";
      return false;
    }
  }

  if (missing_events_.size()) {
    LOG(WARNING) << "The following functions were found in the trace file but "
                 << "are not supported by this grinder:";

    for (auto& event_name : missing_events_) {
      LOG(WARNING) << event_name;
    }
  }

  // TODO(chrisha): Implement this
  return false;
}

bool MemReplayGrinder::OutputData(FILE* file) {
  DCHECK_NE(static_cast<FILE*>(nullptr), file);
  // TODO(chrisha): Implement this
  return false;
}

void MemReplayGrinder::OnFunctionNameTableEntry(
    base::Time time,
    DWORD process_id,
    const TraceFunctionNameTableEntry* data) {
  DCHECK_NE(static_cast<TraceFunctionNameTableEntry*>(nullptr), data);

  if (parse_error_)
    return;

  std::string name(data->name);
  auto it = function_enum_map_.find(name);
  if (it == function_enum_map_.end()) {
    missing_events_.insert(name);
    return;
  }

  ProcessData* proc_data = FindOrCreateProcessData(process_id);
  auto result = proc_data->function_id_map.insert(
      std::make_pair(data->function_id, it->second));
  DCHECK(result.second);

  // If the pending function ID set is now empty then the pending detailed
  // function call records can be drained.
  if (proc_data->pending_function_ids.erase(data->function_id) == 1 &&
      proc_data->pending_function_ids.empty() &&
      !proc_data->pending_calls.empty()) {
    while (!proc_data->pending_calls.empty()) {
      const PendingDetailedFunctionCall& pending_call =
          proc_data->pending_calls.front();
      if (!ParseDetailedFunctionCall(pending_call.time(),
                                     pending_call.thread_id(),
                                     pending_call.data(), proc_data)) {
        return SetParseError();
      }
      proc_data->pending_calls.pop_front();
    }
  }
}

void MemReplayGrinder::OnDetailedFunctionCall(
    base::Time time,
    DWORD process_id,
    DWORD thread_id,
    const TraceDetailedFunctionCall* data) {
  DCHECK_NE(0u, process_id);
  DCHECK_NE(0u, thread_id);
  DCHECK_NE(static_cast<TraceDetailedFunctionCall*>(nullptr), data);

  if (parse_error_)
    return;

  ProcessData* proc_data = FindOrCreateProcessData(process_id);
  DCHECK_NE(static_cast<ProcessData*>(nullptr), proc_data);

  // Lookup the function name.
  const auto& function = proc_data->function_id_map.find(data->function_id);
  if (function == proc_data->function_id_map.end()) {
    // If the function name doesn't exist then the call can't be processed.
    // Push it to the pending list and defer its processing until the function
    // name has been resolved.
    proc_data->pending_function_ids.insert(data->function_id);
    proc_data->pending_calls.push_back(
        PendingDetailedFunctionCall(time, thread_id, data));
    return;
  }

  // The function name exists so parse the record immediately.
  if (!ParseDetailedFunctionCall(time, thread_id, data, proc_data))
    return SetParseError();
}

void MemReplayGrinder::LoadAsanFunctionNames() {
  function_enum_map_.clear();
  for (size_t i = 0; i < arraysize(kAsanHeapFunctionNames); ++i) {
    function_enum_map_[kAsanHeapFunctionNames[i]] =
        static_cast<EventType>(EventInterface::kGetProcessHeapEvent + i);
  }
}

bool MemReplayGrinder::ParseDetailedFunctionCall(
    base::Time time,
    DWORD thread_id,
    const TraceDetailedFunctionCall* data,
    ProcessData* proc_data) {
  DCHECK_NE(static_cast<ProcessData*>(nullptr), proc_data);

  // Lookup the function name. It is expected to exist.
  const auto& function = proc_data->function_id_map.find(data->function_id);
  if (function == proc_data->function_id_map.end())
    return false;

  // Parse the arguments.
  RawArgumentConverters args;
  if (!BuildArgumentConverters(data, &args))
    return false;

  // Get the associated plotline. This should not fail.
  bard::Story::PlotLine* plot_line = FindOrCreatePlotLine(proc_data, thread_id);
  DCHECK_NE(static_cast<bard::Story::PlotLine*>(nullptr), plot_line);

  scoped_ptr<bard::EventInterface> evt;

  switch (function->second) {
    case EventType::kGetProcessHeapEvent: {
      ArgumentParser<HANDLE> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::GetProcessHeapEvent(parser.arg0()));
      break;
    }

    case EventType::kHeapAllocEvent: {
      ArgumentParser<HANDLE, DWORD, SIZE_T, LPVOID> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapAllocEvent(parser.arg0(), parser.arg1(),
                                                 parser.arg2(), parser.arg3()));
      break;
    }

    case EventType::kHeapCreateEvent: {
      ArgumentParser<DWORD, SIZE_T, SIZE_T, HANDLE> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapCreateEvent(
          parser.arg0(), parser.arg1(), parser.arg2(), parser.arg3()));
      break;
    }

    case EventType::kHeapDestroyEvent: {
      ArgumentParser<HANDLE, BOOL> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(
          new bard::events::HeapDestroyEvent(parser.arg0(), parser.arg1()));
      break;
    }

    case EventType::kHeapFreeEvent: {
      // HeapFree calls also contain an optional hash of the memory contents.
      // This is ignored by this grinder.
      ArgumentParser<HANDLE, DWORD, LPVOID, BOOL, uint32_t> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapFreeEvent(parser.arg0(), parser.arg1(),
                                                parser.arg2(), parser.arg3()));
      break;
    }

    case EventType::kHeapReAllocEvent: {
      ArgumentParser<HANDLE, DWORD, LPVOID, SIZE_T, LPVOID> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapReAllocEvent(parser.arg0(), parser.arg1(),
                                                   parser.arg2(), parser.arg3(),
                                                   parser.arg4()));
      break;
    }

    case EventType::kHeapSetInformationEvent: {
      ArgumentParser<HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T, BOOL>
          parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapSetInformationEvent(
          parser.arg0(), parser.arg1(), parser.arg2(), parser.arg3(),
          parser.arg4()));
      break;
    }

    case EventType::kHeapSizeEvent: {
      ArgumentParser<HANDLE, DWORD, LPCVOID, SIZE_T> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapSizeEvent(parser.arg0(), parser.arg1(),
                                                parser.arg2(), parser.arg3()));
      break;
    }

    default: {
      LOG(ERROR) << "Encountered unsupported DetailedFunctionCall record.";
      return false;
    }
  }

  plot_line->push_back(evt.Pass());
  return true;
}

void MemReplayGrinder::SetParseError() {
  parse_error_ = true;
}

MemReplayGrinder::PendingDetailedFunctionCall::PendingDetailedFunctionCall(
    base::Time time,
    DWORD thread_id,
    const TraceDetailedFunctionCall* data)
    : time_(time), thread_id_(thread_id) {
  DCHECK_NE(0u, thread_id);
  DCHECK_NE(static_cast<TraceDetailedFunctionCall*>(nullptr), data);

  size_t total_size = offsetof(TraceDetailedFunctionCall, argument_data) +
                      data->argument_data_size;
  data_.resize(total_size);
  ::memcpy(data_.data(), data, total_size);
}

MemReplayGrinder::ProcessData* MemReplayGrinder::FindOrCreateProcessData(
    DWORD process_id) {
  auto it = process_data_map_.lower_bound(process_id);
  if (it != process_data_map_.end() && it->first == process_id)
    return &it->second;

  scoped_ptr<bard::Story> story(new bard::Story());
  it = process_data_map_.insert(it, std::make_pair(process_id, ProcessData()));
  it->second.process_id = process_id;
  it->second.story = story.get();
  stories_.push_back(story.Pass());
  return &it->second;
}

bard::Story::PlotLine* MemReplayGrinder::FindOrCreatePlotLine(
    ProcessData* proc_data,
    DWORD thread_id) {
  auto it = proc_data->plot_line_map.lower_bound(thread_id);
  if (it != proc_data->plot_line_map.end() && it->first == thread_id)
    return it->second;

  bard::Story::PlotLine* plot_line = proc_data->story->CreatePlotLine();
  proc_data->plot_line_map.insert(it, std::make_pair(thread_id, plot_line));
  return plot_line;
}

}  // namespace grinders
}  // namespace grinder
