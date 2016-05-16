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
//
// Declares the MemReplayGrinder class, which processes trace files
// containing the list of heap accesses and outputs a test scenario
// for replay.
#ifndef SYZYGY_GRINDER_GRINDERS_MEM_REPLAY_GRINDER_H_
#define SYZYGY_GRINDER_GRINDERS_MEM_REPLAY_GRINDER_H_

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "syzygy/bard/event.h"
#include "syzygy/bard/story.h"
#include "syzygy/bard/events/linked_event.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {
namespace grinders {

// This class processes trace files containing the raw history of
// of heap allocations and deallocations, and generates a reduced
// trace file to be used as a test scenario.
class MemReplayGrinder : public GrinderInterface {
 public:
  MemReplayGrinder();
  ~MemReplayGrinder() override {}

  // @name GrinderInterface implementation.
  // @{
  bool ParseCommandLine(const base::CommandLine* command_line) override;
  void SetParser(Parser* parser) override;
  bool Grind() override;
  bool OutputData(FILE* file) override;
  // @}

  // @name ParserEventHandler implementation.
  // @{
  void OnFunctionNameTableEntry(
      base::Time time,
      DWORD process_id,
      const TraceFunctionNameTableEntry* data) override;
  void OnDetailedFunctionCall(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceDetailedFunctionCall* data) override;
  void OnProcessHeap(base::Time time,
                     DWORD process_id,
                     const TraceProcessHeap* data) override;
  // @}

  // Protected for unittesting.
 protected:
  using EventInterface = bard::EventInterface;
  using EventType = EventInterface::EventType;

  // See below for comments and definitions.
  class PendingDetailedFunctionCall;
  class ObjectInfo;
  struct EventObjects;
  struct ProcessData;
  struct ThreadData;
  struct ThreadDataIterator;
  struct ThreadDataIteratorHashFunctor;

  using PendingDetailedFunctionCalls = std::deque<PendingDetailedFunctionCall>;
  // Associates objects by addresses in the trace file to the event in which
  // they are created/destroyed, and if they are alive or not. The event is
  // encoded by the ThreadDataIterator referring to it.
  using ObjectMap = std::unordered_map<const void*, ObjectInfo>;
  // A collection of objects describing a dependency.
  using Deps =
      std::unordered_set<ThreadDataIterator, ThreadDataIteratorHashFunctor>;
  // Tracks dependencies that have already been explicitly encoded. A thread
  // |i| that has already waited on a thread |j| will store the most recent
  // event waited on in the map associated with key (i, j).
  using PlotLinePair =
      std::pair<const bard::Story::PlotLine*, const bard::Story::PlotLine*>;
  using WaitedMap = std::map<PlotLinePair, ThreadDataIterator>;

  // Loads the function_enum_map_ with SyzyASan function names.
  void LoadAsanFunctionNames();
  // Parses a detailed function call record.
  bool ParseDetailedFunctionCall(base::Time time,
                                 DWORD thread_id,
                                 const TraceDetailedFunctionCall* data,
                                 ProcessData* proc_data);
  // Sets parse_error_ to true.
  void SetParseError();
  // Finds or creates the process data for a given process.
  // @param process_id The ID of the process.
  // @returns the associated ProcessData.
  ProcessData* FindOrCreateProcessData(DWORD process_id);
  // Finds or creates the thread data in the provided process data, for the
  // provided thread.
  // @param proc_data The process data.
  // @param thread_id The ID of the thread.
  // @returns the associated ThreadData.
  ThreadData* FindOrCreateThreadData(ProcessData* proc_data, DWORD thread_id);

  // Ensures that the given event is a LinkedEvent, and thus able to support
  // dependencies.
  // @param iter The iterator pointing to the event to be converted.
  void EnsureLinkedEvent(const ThreadDataIterator& iter);
  // Populates the list of objects that are created/destroyed/used by a given
  // event.
  // @param iter The iterator pointing to the event to be queried.
  // @param objects Pointer to the list of objects to be populated.
  void GetEventObjects(const ThreadDataIterator& iter, EventObjects* objects);
  // Gets the set of dependencies for the given event from the given object
  // map.
  // @param iter The iterator pointing to the event to be queried.
  // @param objects The objects created/destroyed/used by the event.
  // @param object_map The map describing the state of all known objects.
  // @param deps A list of events that are dependencies to the event in
  //     @p iter.
  // @returns true on success, false otherwise.
  bool GetDeps(const ThreadDataIterator& iter,
               const EventObjects& objects,
               const ObjectMap& object_map,
               Deps* deps);
  // Updates @p deps with a dependency from @p iter to the provided @p input.
  // Does some analysis to omit adding redundant dependencies.
  // @param iter The iterator pointing to the event with dependencies.
  // @param input The iterator pointing to the input dependency event.
  // @param deps The list of dependencies to be modified.
  void AddDep(const ThreadDataIterator& iter,
              const ThreadDataIterator& input,
              Deps* deps);
  // Applies the given set of dependencies to provided event, updating the
  // @p waited_map.
  // @param iter The iterator pointing to the event with dependencies.
  // @param object_map The map describing the state of all known objects.
  // @param deps The list of input dependencies.
  // @param waited_map The map of already expressed dependencies to be updated.
  bool ApplyDeps(const ThreadDataIterator& iter,
                 const ObjectMap& object_map,
                 const Deps& deps,
                 WaitedMap* waited_map);
  // Updates the provided @p live_object_map and @p dead_object_map with
  // information from the event pointed to by @p iter.
  // @param iter The iterator pointing to the event being processed.
  // @param objects The list of objects touched by the event.
  // @param object_map The map describing the state of all known objects that
  //     is to be updated.
  // @returns true on success, false otherwise.
  bool UpdateObjectMap(const ThreadDataIterator& iter,
                       const EventObjects& objects,
                       ObjectMap* object_map);

  // A map of recognized function names to EventType. If it's name isn't
  // in this map before grinding starts then the function will not be parsed.
  std::map<std::string, EventType> function_enum_map_;
  // The set of unrecognized function names. Any functions that are encountered
  // but not found in |function_enum_map_| will be recorded here for logging
  // purposes.
  std::set<std::string> missing_events_;

  // Storage for stories and plotlines. Stories are kept separate from the
  // ProcessData that indexes them so that the ProcessData can remain easily
  // copyable and compatible with STL containers.
  ScopedVector<bard::Story> stories_;
  std::map<DWORD, ProcessData> process_data_map_;

  // Set to true if a parse error occurs.
  bool parse_error_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemReplayGrinder);
};

// DetailedFunctionCall records can only be parsed if the required
// FunctionNameTable record has already been parsed. Unfortunately, these can
// arrive out of order so sometimes the function call parsing needs to be
// deferred. This structure houses the necessary information (effectively the
// input arguments to OnDetailedFunctionCall).
class MemReplayGrinder::PendingDetailedFunctionCall {
 public:
  PendingDetailedFunctionCall(base::Time time,
                              DWORD thread_id,
                              const TraceDetailedFunctionCall* data);

  const base::Time& time() const { return time_; }
  DWORD thread_id() const { return thread_id_; }
  const TraceDetailedFunctionCall* data() const {
    return reinterpret_cast<const TraceDetailedFunctionCall*>(data_.data());
  }

 private:
  base::Time time_;
  DWORD thread_id_;
  std::vector<uint8_t> data_;
};

// Houses timestamps and PlotLine data associated with a thread ID. This is
// indexed by thread ID in a containing ProcessData.
struct MemReplayGrinder::ThreadData {
  ThreadData() : plot_line(nullptr) {}

  // The timestamps associated with the events in the plot line.
  std::vector<uint64_t> timestamps;
  // The PlotLine representing the events in this thread.
  bard::Story::PlotLine* plot_line;
};

// Houses all data associated with a single process during grinding. This is
// indexed in a map by |process_id|.
struct MemReplayGrinder::ProcessData {
  ProcessData() : process_id(0), story(nullptr) {}

  // The process ID.
  DWORD process_id;
  // All pre-existing heaps. The first is the process heap.
  std::vector<const void*> existing_heaps;
  // Map from trace file function ID to EventType enumeration.
  std::map<uint32_t, EventType> function_id_map;
  // The set of function IDs for which definitions have not yet been seen.
  // When this set is drained all the pending_calls can be processed.
  std::unordered_set<uint32_t> pending_function_ids;
  // The list of detailed function calls that is pending processing.
  PendingDetailedFunctionCalls pending_calls;
  // The story holding events for this process. Ownership is external
  // to this object.
  bard::Story* story;
  // A map of thread ID to the associated thread data.
  std::map<DWORD, ThreadData> thread_data_map;
};

// An iterator-like object for events in a story, sorted by their associated
// timestamp.
struct MemReplayGrinder::ThreadDataIterator {
  uint64_t timestamp() const { return thread_data->timestamps[index]; }

  bard::Story::PlotLine* plot_line() const { return thread_data->plot_line; }

  bard::EventInterface* event() const {
    return (*thread_data->plot_line)[index];
  }

  const bard::EventInterface* inner_event() const {
    auto evt = event();
    if (evt->type() != EventInterface::kLinkedEvent)
      return evt;
    auto e = reinterpret_cast<const bard::events::LinkedEvent*>(evt);
    return e->event();
  }

  // STL heaps are max heaps, so the comparison operator is reversed to create
  // a min heap.
  bool operator<(const ThreadDataIterator& rhs) const {
    return timestamp() > rhs.timestamp();
  }

  // Increments this iterator. Returns true if there are events remaining
  // in the associated plot line.
  bool increment() {
    ++index;
    return index < thread_data->timestamps.size();
  }

  // Comparison operator required for use in unordered_set.
  bool operator==(const ThreadDataIterator& rhs) const {
    return thread_data == rhs.thread_data && index == rhs.index;
  }

  ThreadData* thread_data;
  size_t index;
};

struct MemReplayGrinder::ThreadDataIteratorHashFunctor {
  size_t operator()(const ThreadDataIterator& tdi) const {
    return reinterpret_cast<size_t>(tdi.thread_data) ^ tdi.index;
  }
};

// A small structure for housing information about an object during
// grinding.
class MemReplayGrinder::ObjectInfo {
 public:
  using LastUseMap = std::unordered_map<ThreadData*, size_t>;

  explicit ObjectInfo(const ThreadDataIterator& iter);

  // Gets events associated with this object.
  bool alive() const { return alive_; }
  const ThreadDataIterator& created() const { return created_; }
  const ThreadDataIterator& destroyed() const { return destroyed_; }
  const LastUseMap& last_use() const { return last_use_; }

  void SetCreated(const ThreadDataIterator& iter);
  void SetLastUse(const ThreadDataIterator& iter);
  void SetDestroyed(const ThreadDataIterator& iter);

 private:
  // Disallow use of the default constructor.
  ObjectInfo() {}

  // Indicates whether or not the object is alive.
  bool alive_;

  // The events that create and destroy this object.
  ThreadDataIterator created_;
  ThreadDataIterator destroyed_;

  // Per thread, the most recent use of this object. This map uses an exploded
  // ThreadDataIterator as key and value.
  LastUseMap last_use_;

  // Copy and assignment is allowed in order to keep this object compatible
  // with STL containers.
};

// Houses inputs and outputs of an input, by type.
struct MemReplayGrinder::EventObjects {
  void* created;
  void* destroyed;
  std::vector<void*> used;
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_MEM_REPLAY_GRINDER_H_
