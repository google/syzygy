// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/asan_flags.h"

#include <string>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/string_number_conversions.h"
#include "base/sys_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/asan_heap.h"

namespace agent {
namespace asan {

namespace {

bool UpdateSizetFromCommandLine(const CommandLine& cmd_line,
                                const std::string& param_name,
                                size_t* value) {
  if (cmd_line.HasSwitch(param_name)) {
    std::string value_str = cmd_line.GetSwitchValueASCII(param_name);
    size_t new_value = 0;
    if (!base::StringToSizeT(value_str, &new_value))
      return false;
    *value = new_value;
  }
  return true;
}

base::LazyInstance<FlagsManager> static_flags_manager_instance =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

const char FlagsManager::kQuarantineSize[] = "quarantine_size";
const char FlagsManager::kCompressionReportingPeriod[] =
    "compression_reporting_period";

const char FlagsManager::kSyzyAsanEnvVar[] = "ASAN_OPTIONS";

FlagsManager::FlagsManager() {
}

FlagsManager::~FlagsManager() {
}

FlagsManager* FlagsManager::Instance() {
  return static_flags_manager_instance.Pointer();
}

bool FlagsManager::ParseFlagsFromString(const std::wstring& str) {
  CommandLine cmd_line = CommandLine::FromString(str);

  size_t quarantine_size = HeapProxy::GetDefaultQuarantineMaxSize();
  if (!UpdateSizetFromCommandLine(cmd_line, kQuarantineSize,
                                  &quarantine_size)) {
    LOG(ERROR) << "Unable to read " << kQuarantineSize << " from the argument "
               << "list.";
    return false;
  }
  HeapProxy::SetDefaultQuarantineMaxSize(quarantine_size);

  size_t reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod();
  if (!UpdateSizetFromCommandLine(cmd_line, kCompressionReportingPeriod,
                                  &reporting_period)) {
    LOG(ERROR) << "Unable to read " << kCompressionReportingPeriod
               << " from the argument list.";
    return false;
  }
  StackCaptureCache::SetCompressionReportingPeriod(reporting_period);

  return true;
}

bool FlagsManager::InitializeFlagsWithEnvVar() {
  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string env_var_str;
  if (!env->GetVar(kSyzyAsanEnvVar, &env_var_str)) {
    return true;
  }
  // Prepends the flags with the agent name. We need to do this because the
  // command-line constructor expect the process name to be the first value of
  // the command-line string.
  env_var_str.insert(0, "asan_rtl.dll ");
  std::wstring env_var_wstr = base::SysUTF8ToWide(env_var_str);

  if (!ParseFlagsFromString(env_var_wstr))
    return false;
  return true;
}

}  // namespace asan
}  // namespace agent
