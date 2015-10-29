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
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/memory/scoped_ptr.h"
#include "syzygy/bard/event.h"
#include "syzygy/bard/story.h"
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
  // @}

  // Protected for unittesting.
 protected:
  using EventInterface = bard::EventInterface;
  using EventType = EventInterface::EventType;

  // DetailedFunctionCall records can only be parsed if the required
  // FunctionNameTable record has already been parsed. Unfortunately, these can
  // arrive out of order so sometimes the function call parsing needs to be
  // deferred. This structure houses the necessary information (effectively the
  // input arguments to OnDetailedFunctionCall).
  class PendingDetailedFunctionCall {
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
    std::vector<uint8> data_;
  };
  using PendingDetailedFunctionCalls = std::deque<PendingDetailedFunctionCall>;

  // Houses all data associated with a single process during grinding. This is
  // indexed in a map by |process_id|.
  struct ProcessData {
    ProcessData() : process_id(0), story(nullptr) {}

    // The process ID.
    DWORD process_id;
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
    // A map of thread ID to the associated PlotLine in |story|.
    std::map<DWORD, bard::Story::PlotLine*> plot_line_map;
  };

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
  ProcessData* FindOrCreateProcessData(DWORD process_id);
  // Finds or creates the plot-line in the provided process data, for the
  // provided thread.
  bard::Story::PlotLine* FindOrCreatePlotLine(ProcessData* proc_data,
                                              DWORD thread_id);

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

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_MEM_REPLAY_GRINDER_H_
