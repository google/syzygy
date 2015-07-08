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

MemReplayGrinder::MemReplayGrinder() {
}

MemReplayGrinder::~MemReplayGrinder() {
}

bool MemReplayGrinder::ParseCommandLine(
    const base::CommandLine* command_line) {
  DCHECK_NE(static_cast<base::CommandLine*>(nullptr), command_line);
  // TODO(rubensf): Implement this
  return false;
}

void MemReplayGrinder::SetParser(Parser* parser) {
  DCHECK_NE(static_cast<Parser*>(nullptr), parser);
  // TODO(rubensf): Implement this
}

bool MemReplayGrinder::Grind() {
  // TODO(rubensf): Implement this
  return false;
}

bool MemReplayGrinder::OutputData(FILE* file) {
  DCHECK_NE(static_cast<FILE*>(nullptr), file);
  // TODO(rubensf): Implement this
  return false;
}

}  // namespace grinders
}  // namespace grinder
