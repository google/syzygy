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

#include <map>
#include <utility>

#include "syzygy/bard/event.h"
#include "syzygy/bard/events/linked_event.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {
namespace grinders {

// This class processes trace files containing the raw history of
// of heap allocations and deallocations, and generates a reduced
// trace file to be used as a test scenario.
class MemReplayGrinder : public GrinderInterface {
 public:
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
  // @}

  // Protected for unittesting.
 protected:
  // Key for storing function names by process and id.
  using ProcessFunctionIdPair = std::pair<DWORD, uint32_t>;
  using EventInterface = bard::EventInterface;
  using EventType = EventInterface::EventType;

  // Loads the function_enum_map_ with SyzyASan function names.
  void LoadAsanFunctionNames();

  std::map<ProcessFunctionIdPair, EventType> process_id_enum_map_;
  std::map<std::string, EventType> function_enum_map_;
  std::set<std::string> missing_events_;
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_MEM_REPLAY_GRINDER_H_
