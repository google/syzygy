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
// Declares structures and parsing routines for Memory Profiler runtime
// parameters.

#ifndef SYZYGY_AGENT_MEMPROF_PARAMETERS_H_
#define SYZYGY_AGENT_MEMPROF_PARAMETERS_H_

#include "base/strings/string_piece.h"
#include "syzygy/common/assertions.h"

namespace agent {
namespace memprof {

// Describes how the module tracks stack traces.
enum StackTraceTracking {
  // Stack traces will be ignored.
  kTrackingNone,
  // Stack traces will be tracked, and IDs emitted along with
  // DetailedFunctionCall records.
  kTrackingTrack,
  // Stack traces will be both tracked and emitted as StackTrace records.
  kTrackingEmit,

  // Must be last.
  kStackTraceTrackingMax,
};

// A structure housing runtime paramters for the memory profiler agent.
struct Parameters {
  // Controls the level of detail stored in |stack_trace_id|.
  StackTraceTracking stack_trace_tracking;
  // If this is enabled then timestamps are strictly serialized and
  // synchronized across all threads.
  bool serialize_timestamps;
  // If this is enabled then block contents will be hashed when freed, and
  // the hash value stored as an additional parameter to the heap free
  // function.
  bool hash_contents_at_free;
};

// The environment variable that is used for extracting parameters.
extern const char kParametersEnvVar[];

// An array mapping StackTraceTracking values to strings.
extern const char* kStackTraceTrackingValues[];

// Default parameter values.
extern StackTraceTracking kDefaultStackTraceTracking;
extern bool kDefaultSerializeTimestamps;
extern bool kDefaultHashContentsAtFree;

// Parameter names for parsing.
extern const char kParamStackTraceTracking[];
extern const char kParamSerializeTimestamps[];
extern const char kParamHashContentsAtFree[];

// Initializes a Parameters struct with default values.
// @param parameters The Parameters struct to be initialized.
void SetDefaultParameters(Parameters* parameters);

// Parses parameters from a string and updates the provided structure.
// @param param_string the string of parameters to be parsed.
// @param parameters The Parameters struct to be updated.
// @returns true on success, false otherwise. Logs verbosely on failure.
bool ParseParameters(const base::StringPiece& param_string,
                     Parameters* parameters);

// Parses parameters from the environment and updates the provided structure.
// @param parameters The Parameters struct to be updated.
// @returns true on success, false otherwise. Logs verbosely on failure.
bool ParseParametersFromEnv(Parameters* parameters);

}  // namespace memprof
}  // namespace agent

#endif  // SYZYGY_AGENT_MEMPROF_PARAMETERS_H_
