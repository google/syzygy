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

namespace grinder {
namespace grinders {

namespace {

const char* kAsanHeapFunctionNames[] = {
    "asan_GetProcessHeap",
    "asan_HeapAlloc",
    "asan_HeapCreateap",
    "asan_HeapDestroy",
    "asan_HeapFree",
    "asan_HeapReAlloc",
    "asan_HeapSetInformation",
    "asan_HeapSize",
};

}  // namespace

bool MemReplayGrinder::ParseCommandLine(
    const base::CommandLine* command_line) {
  DCHECK_NE(static_cast<base::CommandLine*>(nullptr), command_line);
  // TODO(rubensf): Add a switch for choosing which function names to use.
  LoadAsanFunctionNames();

  return true;
}

void MemReplayGrinder::SetParser(Parser* parser) {
  DCHECK_NE(static_cast<Parser*>(nullptr), parser);
  // TODO(rubensf): Implement this
}

bool MemReplayGrinder::Grind() {
  if (missing_events_.size()) {
    LOG(WARNING) << "The following functions were found in the trace file but "
                 << "are not supported by this grinder:";

    for (auto event_name : missing_events_) {
      LOG(WARNING) << event_name;
    }
  }

  // TODO(rubensf): Implement this
  return false;
}

bool MemReplayGrinder::OutputData(FILE* file) {
  DCHECK_NE(static_cast<FILE*>(nullptr), file);
  // TODO(rubensf): Implement this
  return false;
}

void MemReplayGrinder::OnFunctionNameTableEntry(
    base::Time time,
    DWORD process_id,
    const TraceFunctionNameTableEntry* data) {
  DCHECK_NE(static_cast<TraceFunctionNameTableEntry*>(nullptr), data);
  std::string name(data->name);

  auto it = function_enum_map_.find(name);

  if (it == function_enum_map_.end()) {
    missing_events_.insert(name);
    return;
  }

  auto result = process_id_enum_map_.insert(std::make_pair(
      ProcessFunctionIdPair(process_id, data->function_id), it->second));

  DCHECK_EQ(it->second, result.first->second);
}

void MemReplayGrinder::LoadAsanFunctionNames() {
  function_enum_map_.clear();
  for (size_t i = 0; i < EventType::kMaxEventType; ++i) {
    function_enum_map_[kAsanHeapFunctionNames[static_cast<EventType>(i)]] =
        static_cast<EventType>(EventInterface::kGetProcessHeapEvent + i);
  }
}

}  // namespace grinders
}  // namespace grinder
