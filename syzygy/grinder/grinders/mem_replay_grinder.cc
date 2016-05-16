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
#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_realloc_event.h"
#include "syzygy/bard/events/heap_set_information_event.h"
#include "syzygy/bard/events/heap_size_event.h"
#include "syzygy/core/serialization.h"
#include "syzygy/core/zstream.h"

namespace grinder {
namespace grinders {

namespace {

const char* kAsanHeapFunctionNames[] = {
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
bool ParseUint32(const uint8_t* end, const uint8_t** cursor, uint32_t* value) {
  DCHECK_NE(static_cast<uint8_t*>(nullptr), end);
  DCHECK_NE(static_cast<uint8_t**>(nullptr), cursor);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), *cursor);
  DCHECK_LE(*cursor, end);
  DCHECK_NE(static_cast<uint32_t*>(nullptr), value);

  if (std::distance(*cursor, end) < sizeof(*value))
    return false;
  *value = *reinterpret_cast<const uint32_t*>(*cursor);
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

  // Grind each set of process data on its own.
  for (auto& proc : process_data_map_) {
    // Make a heap of events across all threads in this process.
    std::vector<ThreadDataIterator> heap;
    for (auto& thread : proc.second.thread_data_map) {
      if (thread.second.timestamps.empty())
        continue;
      ThreadDataIterator thread_it = {&thread.second, 0};
      heap.push_back(thread_it);
    }
    std::make_heap(heap.begin(), heap.end());

    // This is used to track known objects.
    ObjectMap object_map;
    // This is used to track synchronization points between threads.
    WaitedMap waited_map;

    // Prepopulate the object map with entries for all the process heaps that
    // existed at process startup.
    const ThreadDataIterator kDummyThreadDataIterator = {nullptr, 0};
    const ObjectInfo kDummyObjectInfo(kDummyThreadDataIterator);
    for (auto heap : proc.second.existing_heaps)
      object_map.insert(std::make_pair(heap, kDummyObjectInfo));

    // Process all of the thread events in the serial order in which they
    // occurred. While doing so update object_map and waited_map, and encode
    // dependencies in the underlying PlotLine structures.
    while (!heap.empty()) {
      std::pop_heap(heap.begin(), heap.end());
      auto thread_it = heap.back();
      heap.pop_back();

      // Determine inputs and outputs of this event.
      EventObjects objects;
      GetEventObjects(thread_it, &objects);

      // Determine input dependencies for this event.
      Deps deps;
      if (!GetDeps(thread_it, objects, object_map, &deps))
        return false;

      // Encode dependencies as explicit synchronization points as required,
      // and update the |waited_map| with this information.
      if (!ApplyDeps(thread_it, object_map, deps, &waited_map))
        return false;

      // Update the object map to reflect objects that have been destroyed,
      // created, or used.
      if (!UpdateObjectMap(thread_it, objects, &object_map))
        return false;

      // Increment the thread event iterator and reinsert it in the heap if
      // there are remaining events.
      if (thread_it.increment()) {
        heap.push_back(thread_it);
        std::push_heap(heap.begin(), heap.end());
      }
    }
  }

  return true;
}

bool MemReplayGrinder::OutputData(FILE* file) {
  DCHECK_NE(static_cast<FILE*>(nullptr), file);

  if (process_data_map_.empty())
    return false;

  // Set up the streams/archives for serialization. Using gzip compression
  // reduces the size of the archive by over 70%.
  core::FileOutStream out_stream(file);
  core::ZOutStream zout_stream(&out_stream);
  core::NativeBinaryOutArchive out_archive(&zout_stream);
  if (!zout_stream.Init(9))
    return false;

  // Save a magic header and version so that readers can validate the stream.
  if (!out_archive.Save(bard::Story::kBardMagic))
    return false;
  if (!out_archive.Save(bard::Story::kBardVersion))
    return false;

  // Serialize the stories, back to back.
  if (!out_archive.Save(static_cast<size_t>(process_data_map_.size())))
    return false;
  for (const auto& proc_data_pair : process_data_map_) {
    // Output any existing heaps. The first of these is the process heap.
    size_t heap_count = proc_data_pair.second.existing_heaps.size();
    if (!out_archive.Save(heap_count))
      return false;
    for (const auto& heap : proc_data_pair.second.existing_heaps) {
      if (!out_archive.Save(reinterpret_cast<uintptr_t>(heap)))
        return false;
    }

    // Output the story.
    auto story = proc_data_pair.second.story;
    if (!story->Save(&out_archive))
      return false;
  }

  // Ensure everything is written.
  if (!zout_stream.Flush())
    return false;
  if (!out_stream.Flush())
    return false;

  return true;
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

  // If function calls are already pending then all new calls must continue to
  // be added to the pending list.
  bool push_pending = !proc_data->pending_calls.empty();

  // If the function name doesn't exist then the call can't be processed.
  // Push it to the pending list and defer its processing until the function
  // name has been resolved.
  const auto& function = proc_data->function_id_map.find(data->function_id);
  if (function == proc_data->function_id_map.end()) {
    proc_data->pending_function_ids.insert(data->function_id);
    push_pending = true;
  }

  // Defer processing if required.
  if (push_pending) {
    proc_data->pending_calls.push_back(
        PendingDetailedFunctionCall(time, thread_id, data));
    return;
  }

  // The function name exists and there are no pending calls so parse the record
  // immediately.
  DCHECK(function != proc_data->function_id_map.end());
  DCHECK(proc_data->pending_calls.empty());
  if (!ParseDetailedFunctionCall(time, thread_id, data, proc_data))
    return SetParseError();
}

void MemReplayGrinder::OnProcessHeap(base::Time time,
                                     DWORD process_id,
                                     const TraceProcessHeap* data) {
  DCHECK_NE(0u, process_id);
  DCHECK_NE(static_cast<TraceProcessHeap*>(nullptr), data);
  DCHECK_NE(0u, data->process_heap);

  if (parse_error_)
    return;

  ProcessData* proc_data = FindOrCreateProcessData(process_id);
  DCHECK_NE(static_cast<ProcessData*>(nullptr), proc_data);
  proc_data->existing_heaps.push_back(
      reinterpret_cast<const void*>(data->process_heap));
}

void MemReplayGrinder::LoadAsanFunctionNames() {
  function_enum_map_.clear();
  for (size_t i = 0; i < arraysize(kAsanHeapFunctionNames); ++i) {
    function_enum_map_[kAsanHeapFunctionNames[i]] =
        static_cast<EventType>(EventInterface::kHeapAllocEvent + i);
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

  // Get the associated thread data. This should not fail.
  ThreadData* thread_data = FindOrCreateThreadData(proc_data, thread_id);
  DCHECK_NE(static_cast<ThreadData*>(nullptr), thread_data);
  DCHECK_NE(static_cast<bard::Story::PlotLine*>(nullptr),
            thread_data->plot_line);

  std::unique_ptr<bard::EventInterface> evt;

  switch (function->second) {
    case EventType::kHeapAllocEvent: {
      ArgumentParser<HANDLE, DWORD, SIZE_T, LPVOID> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapAllocEvent(data->stack_trace_id,
                                                 parser.arg0(), parser.arg1(),
                                                 parser.arg2(), parser.arg3()));
      break;
    }

    case EventType::kHeapCreateEvent: {
      ArgumentParser<DWORD, SIZE_T, SIZE_T, HANDLE> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapCreateEvent(
          data->stack_trace_id, parser.arg0(), parser.arg1(), parser.arg2(),
          parser.arg3()));
      break;
    }

    case EventType::kHeapDestroyEvent: {
      ArgumentParser<HANDLE, BOOL> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapDestroyEvent(
          data->stack_trace_id, parser.arg0(), parser.arg1()));
      break;
    }

    case EventType::kHeapFreeEvent: {
      // HeapFree calls also contain an optional hash of the memory contents.
      // This is ignored by this grinder.
      ArgumentParser<HANDLE, DWORD, LPVOID, BOOL, uint32_t> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapFreeEvent(data->stack_trace_id,
                                                parser.arg0(), parser.arg1(),
                                                parser.arg2(), parser.arg3()));
      break;
    }

    case EventType::kHeapReAllocEvent: {
      ArgumentParser<HANDLE, DWORD, LPVOID, SIZE_T, LPVOID> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapReAllocEvent(
          data->stack_trace_id, parser.arg0(), parser.arg1(), parser.arg2(),
          parser.arg3(), parser.arg4()));
      break;
    }

    case EventType::kHeapSetInformationEvent: {
      ArgumentParser<HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T, BOOL>
          parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapSetInformationEvent(
          data->stack_trace_id, parser.arg0(), parser.arg1(), parser.arg2(),
          parser.arg3(), parser.arg4()));
      break;
    }

    case EventType::kHeapSizeEvent: {
      ArgumentParser<HANDLE, DWORD, LPCVOID, SIZE_T> parser;
      if (!parser.Parse(args))
        return false;
      evt.reset(new bard::events::HeapSizeEvent(data->stack_trace_id,
                                                parser.arg0(), parser.arg1(),
                                                parser.arg2(), parser.arg3()));
      break;
    }

    default: {
      LOG(ERROR) << "Encountered unsupported DetailedFunctionCall record.";
      return false;
    }
  }

  thread_data->plot_line->push_back(evt.release());
  thread_data->timestamps.push_back(data->timestamp);
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

  std::unique_ptr<bard::Story> story(new bard::Story());
  it = process_data_map_.insert(it, std::make_pair(process_id, ProcessData()));
  it->second.process_id = process_id;
  it->second.story = story.get();
  stories_.push_back(story.release());
  return &it->second;
}

MemReplayGrinder::ThreadData* MemReplayGrinder::FindOrCreateThreadData(
    ProcessData* proc_data,
    DWORD thread_id) {
  auto it = proc_data->thread_data_map.lower_bound(thread_id);
  if (it != proc_data->thread_data_map.end() && it->first == thread_id)
    return &it->second;

  bard::Story::PlotLine* plot_line = proc_data->story->CreatePlotLine();
  ThreadData thread_data;
  thread_data.plot_line = plot_line;
  it = proc_data->thread_data_map.insert(
      it, std::make_pair(thread_id, thread_data));
  return &it->second;
}

void MemReplayGrinder::EnsureLinkedEvent(const ThreadDataIterator& iter) {
  if (iter.event()->type() == EventInterface::kLinkedEvent)
    return;

  bard::events::LinkedEvent* linked_event = new bard::events::LinkedEvent(
      std::unique_ptr<EventInterface>(iter.event()));
  (*iter.plot_line())[iter.index] = linked_event;
}

void MemReplayGrinder::GetEventObjects(const ThreadDataIterator& iter,
                                       EventObjects* objects) {
  DCHECK_NE(static_cast<EventObjects*>(nullptr), objects);

  auto evt = iter.inner_event();
  objects->created = nullptr;
  objects->destroyed = nullptr;
  objects->used.clear();

  // Determine objects that are created, used or destroyed.
  switch (evt->type()) {
    case EventInterface::kHeapAllocEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapAllocEvent*>(iter.event());
      if (e->trace_heap())
        objects->used.push_back(e->trace_heap());
      objects->created = e->trace_alloc();
      break;
    }
    case EventInterface::kHeapCreateEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapCreateEvent*>(iter.event());
      objects->created = e->trace_heap();
      break;
    }
    case EventInterface::kHeapDestroyEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapDestroyEvent*>(iter.event());
      objects->destroyed = e->trace_heap();
      break;
    }
    case EventInterface::kHeapFreeEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapFreeEvent*>(iter.event());
      if (e->trace_heap())
        objects->used.push_back(e->trace_heap());
      objects->destroyed = e->trace_alloc();
      break;
    }
    case EventInterface::kHeapReAllocEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapReAllocEvent*>(iter.event());
      if (e->trace_heap())
        objects->used.push_back(e->trace_heap());

      if (e->trace_alloc() == e->trace_realloc()) {
        // ReAllocs that return the original address are indistinguishable from
        // a simple 'use' of that address. Encode it as such.
        objects->used.push_back(e->trace_alloc());
      } else {
        objects->destroyed = e->trace_alloc();
        objects->created = e->trace_realloc();
      }
      break;
    }
    case EventInterface::kHeapSetInformationEvent: {
      auto e = reinterpret_cast<const bard::events::HeapSetInformationEvent*>(
          iter.event());
      if (e->trace_heap())
        objects->used.push_back(e->trace_heap());
      break;
    }
    case EventInterface::kHeapSizeEvent: {
      auto e =
          reinterpret_cast<const bard::events::HeapSizeEvent*>(iter.event());
      if (e->trace_heap())
        objects->used.push_back(e->trace_heap());
      if (e->trace_alloc())
        objects->used.push_back(const_cast<void*>(e->trace_alloc()));
      break;
    }
    default: break;
  }
}

bool MemReplayGrinder::GetDeps(const ThreadDataIterator& iter,
                               const EventObjects& objects,
                               const ObjectMap& object_map,
                               Deps* deps) {
  DCHECK_NE(static_cast<Deps*>(nullptr), deps);
  DCHECK(deps->empty());

  // If the object being created is aliased to one that has already existed
  // then ensure a dependency to the previous destruction event is generated.
  if (objects.created) {
    auto it = object_map.find(objects.created);
    if (it != object_map.end()) {
      if (it->second.alive()) {
        LOG(ERROR) << "Unable to create existing object: " << objects.created;
        LOG(ERROR) << "  Timestamp: " << std::hex << iter.timestamp();
        return false;
      }
      AddDep(iter, it->second.destroyed(), deps);
    }
  }

  // For each used object, create an input dependency on the creation of that
  // object.
  for (auto used : objects.used) {
    auto it = object_map.find(used);
    if (it == object_map.end() || !it->second.alive()) {
      LOG(ERROR) << "Unable to encode use dependency to dead or missing "
                 << "object: " << used;
      LOG(ERROR) << "  Timestamp: " << std::hex << iter.timestamp();
      return false;
    }
    AddDep(iter, it->second.created(), deps);
  }

  if (objects.destroyed) {
    // For a destroyed object, create an input dependency on the most recent
    // use of that object on each other thread. This ensures that it won't be
    // destroyed during playback until all contemporary uses of it have
    // completed.
    auto it = object_map.find(objects.destroyed);
    if (it == object_map.end() || !it->second.alive()) {
      LOG(ERROR) << "Unable to encode destruction depedendency to dead or "
                 << "missing object: " << objects.destroyed;
      LOG(ERROR) << "  Timestamp: " << std::hex << iter.timestamp();
      return false;
    }
    for (auto thread_index_pair : it->second.last_use()) {
      // Skip uses on this thread, as they are implicit.
      if (thread_index_pair.first == iter.thread_data)
        continue;
      ThreadDataIterator dep = {thread_index_pair.first,
                                thread_index_pair.second};
      AddDep(iter, dep, deps);
    }
  }

  return true;
}

void MemReplayGrinder::AddDep(const ThreadDataIterator& iter,
                              const ThreadDataIterator& input,
                              Deps* deps) {
  DCHECK_NE(static_cast<Deps*>(nullptr), deps);

  // If the dependency is to an object on a dummy thread it doesn't need to be
  // encoded. Such events represent creation events for objects that exist
  // before the playback starts.
  if (input.thread_data == nullptr)
    return;

  // Dependencies can only be to older events.
  DCHECK_LT(input.timestamp(), iter.timestamp());

  // Dependencies to events on the same thread are implicit and need not be
  // encoded.
  if (iter.thread_data->plot_line == input.thread_data->plot_line)
    return;

  deps->insert(input);
}

bool MemReplayGrinder::ApplyDeps(const ThreadDataIterator& iter,
                                 const ObjectMap& object_map,
                                 const Deps& deps,
                                 WaitedMap* waited_map) {
  DCHECK_NE(static_cast<WaitedMap*>(nullptr), waited_map);

  for (auto dep : deps) {
    // Determine if there's already a sufficiently recent encoded dependency
    // between these two plot lines.
    // NOTE: This logic could be generalized to look for paths of dependencies,
    // but that requires significantly more storage and computation. This
    // catches the most common cases.
    auto plot_line_pair = PlotLinePair(iter.plot_line(), dep.plot_line());
    auto waited_it = waited_map->lower_bound(plot_line_pair);
    if (waited_it != waited_map->end() && waited_it->first == plot_line_pair) {
      DCHECK_EQ(dep.plot_line(), waited_it->second.plot_line());
      if (waited_it->second.index >= dep.index)
        continue;
    }

    // Arriving here indicates that the dependency must be explicitly encoded.

    // Update the |waiting_map| to reflect the dependency.
    if (waited_it != waited_map->end() && waited_it->first == plot_line_pair) {
      waited_it->second = dep;
    } else {
      waited_map->insert(waited_it, std::make_pair(plot_line_pair, dep));
    }

    // Make ourselves and the dependency linked events if necessary.
    EnsureLinkedEvent(iter);
    EnsureLinkedEvent(dep);

    // Finally, wire up the dependency.
    reinterpret_cast<bard::events::LinkedEvent*>(iter.event())
        ->AddDep(dep.event());
  }

  return true;
}

bool MemReplayGrinder::UpdateObjectMap(const ThreadDataIterator& iter,
                                       const EventObjects& objects,
                                       ObjectMap* object_map) {
  DCHECK_NE(static_cast<ObjectMap*>(nullptr), object_map);

  // Forward these for readability.
  auto created = objects.created;
  auto destroyed = objects.destroyed;
  auto& used = objects.used;

  // Update the object map to reflect any destroyed objects.
  if (destroyed) {
    auto it = object_map->find(destroyed);
    if (it == object_map->end()) {
      LOG(ERROR) << "Unable to destroy missing object: " << destroyed;
      return false;
    }

    ObjectInfo& info = it->second;
    if (!info.alive()) {
      LOG(ERROR) << "Unable to destroy dead object: " << destroyed;
      return false;
    }

    // Update the object info to reflect the fact that it is now dead, and
    // the event that destroyed it.
    info.SetDestroyed(iter);
  }

  // Update the object map to reflect any created objects.
  if (created) {
    // Insert the created object.
    auto result = object_map->insert(std::make_pair(created, ObjectInfo(iter)));

    // Insertion failed, as the object already existed. This is fine if it was
    // dead, but an error if it was alive.
    if (!result.second) {
      ObjectInfo& info = result.first->second;
      if (info.alive()) {
        LOG(ERROR) << "Unable to create alive object: " << created;
        return false;
      }

      // Transition the object to being alive again.
      info.SetCreated(iter);
    }
  }

  // Update the object map to reflect any used objects.
  for (auto object : used) {
    auto it = object_map->find(object);
    if (it == object_map->end()) {
      LOG(ERROR) << "Unable to use missing object: " << object;
      return false;
    }
    it->second.SetLastUse(iter);
  }

  return true;
}

MemReplayGrinder::ObjectInfo::ObjectInfo(const ThreadDataIterator& iter) {
  SetCreated(iter);
}

void MemReplayGrinder::ObjectInfo::SetCreated(const ThreadDataIterator& iter) {
  alive_ = true;
  created_ = iter;
  destroyed_ = {nullptr, 0};

  last_use_.clear();
  SetLastUse(iter);
}

void MemReplayGrinder::ObjectInfo::SetLastUse(const ThreadDataIterator& iter) {
  last_use_[iter.thread_data] = iter.index;
}

void MemReplayGrinder::ObjectInfo::SetDestroyed(
    const ThreadDataIterator& iter) {
  alive_ = false;
  destroyed_ = iter;
  SetLastUse(iter);
}

}  // namespace grinders
}  // namespace grinder
