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

#include "syzygy/agent/memprof/parameters.h"

#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"

namespace agent {
namespace memprof {

// An array mapping StackTraceTracking values to strings.
const char* kStackTraceTrackingValues[] = {
  "none", "track", "emit",
};
static_assert(arraysize(kStackTraceTrackingValues) == kStackTraceTrackingMax,
              "Stack trace tracking values out of sync.");

// The environment variable that is used for extracting parameters.
const char kParametersEnvVar[] = "SYZYGY_MEMPROF_OPTIONS";

// Default parameter values.
StackTraceTracking kDefaultStackTraceTracking = kTrackingNone;
bool kDefaultSerializeTimestamps = false;
bool kDefaultHashContentsAtFree = false;

// Parameter names for parsing.
const char kParamStackTraceTracking[] = "stack-trace-tracking";
const char kParamSerializeTimestamps[] = "serialize-timestamps";
const char kParamHashContentsAtFree[] = "hash-contents-at-free";

void SetDefaultParameters(Parameters* parameters) {
  DCHECK_NE(static_cast<Parameters*>(nullptr), parameters);
  parameters->stack_trace_tracking = kDefaultStackTraceTracking;
  parameters->serialize_timestamps = false;
  parameters->hash_contents_at_free = false;
}

bool ParseParameters(const base::StringPiece& param_string,
                     Parameters* parameters) {
  DCHECK_NE(static_cast<Parameters*>(nullptr), parameters);

  // Prepends the flags with a dummy executable name to keep the
  // base::CommandLine parser happy.
  std::wstring str = base::UTF8ToWide(param_string);
  str.insert(0, L" ");
  str.insert(0, L"dummy.exe");
  base::CommandLine cmd_line = base::CommandLine::FromString(str);

  bool success = true;

  // Parse the stack trace tracking enum.
  std::string value = cmd_line.GetSwitchValueASCII(kParamStackTraceTracking);
  if (!value.empty()) {
    bool parsed = false;
    for (size_t i = 0; i < kStackTraceTrackingMax; ++i) {
      if (value == kStackTraceTrackingValues[i]) {
        parsed = true;
        parameters->stack_trace_tracking = static_cast<StackTraceTracking>(i);
        break;
      }
    }
    if (!parsed) {
      LOG(ERROR) << "Unknown value for --" << kParamStackTraceTracking
                 << ": " << value;
      success = false;
    }
  }

  if (cmd_line.HasSwitch(kParamSerializeTimestamps))
    parameters->serialize_timestamps = true;

  if (cmd_line.HasSwitch(kParamHashContentsAtFree))
    parameters->hash_contents_at_free = true;

  return success;
}

bool ParseParametersFromEnv(Parameters* parameters) {
  DCHECK_NE(static_cast<Parameters*>(nullptr), parameters);

  std::unique_ptr<base::Environment> env(base::Environment::Create());
  DCHECK_NE(static_cast<base::Environment*>(nullptr), env.get());

  std::string value;
  if (!env->GetVar(kParametersEnvVar, &value))
    return true;

  if (!ParseParameters(value, parameters))
    return false;

  return true;
}

}  // namespace memprof
}  // namespace agent
