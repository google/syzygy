// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/reporters/crashpad_reporter.h"

#include <algorithm>

#include "base/environment.h"
#include "base/strings/utf_string_conversions.h"
#include "client/crashpad_client.h"

namespace agent {
namespace asan {
namespace reporters {

namespace {

// The name of the environment variable that holds the crashpad pipe name.
const char kCrashpadPipeNameVar[] = "CHROME_CRASHPAD_PIPE_NAME";

// The crashpad client. This is used for communicating with the crashpad
// process via IPC.
crashpad::CrashpadClient g_crashpad_client;

// Used for establishing Crashpad IPC channels. This is racy, but the IPC
// mechanism ensures everyone will get the same results and that it's
// inherently safe. Barring people changing the environment variable between
// calls. So, to be completely sure bring your own synchronization.
// NOTE: This entire mechanism is... ugly. It relies on very specific knowledge
// of how Chrome interacts with its instance of a Crashpad handler, and it
// doesn't generalize to other clients. Moving forward we will be adding a
// generic callback mechanism for instrumented clients to inform the RTL of the
// crash handler to use.
bool EnsureCrashpadConnected() {
  static bool initialized = false;
  static bool crashpad_present = false;

  // Only initialize once.
  if (initialized)
    return crashpad_present;
  initialized = true;

  // Get the name of the crashpad endpoint, failing if none exists.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::string pipe_name;
  if (!env->GetVar(kCrashpadPipeNameVar, &pipe_name))
    return false;
  std::wstring pipe_name_w = base::UTF8ToWide(pipe_name);

  // Initialize the crashpad client.
  if (!g_crashpad_client.SetHandlerIPCPipe(pipe_name_w))
    return false;
  if (!g_crashpad_client.UseHandler())
    return false;

  crashpad_present = true;
  return true;
}

}  // namespace

const char CrashpadReporter::kName[] = "CrashpadReporter";

// static
std::unique_ptr<CrashpadReporter> CrashpadReporter::Create() {
  // Create a crashpad reporter only if a crashpad instance is running for this
  // process.
  if (!EnsureCrashpadConnected())
    return nullptr;

  auto crashpad_info = crashpad::CrashpadInfo::GetCrashpadInfo();
  return std::unique_ptr<CrashpadReporter>(new CrashpadReporter(crashpad_info));
}

const char* CrashpadReporter::GetName() const {
  return kName;
}

uint32_t CrashpadReporter::GetFeatures() const {
  return FEATURE_CRASH_KEYS | FEATURE_EARLY_CRASH_KEYS |
      FEATURE_MEMORY_RANGES | FEATURE_CUSTOM_STREAMS |
      FEATURE_DUMP_WITHOUT_CRASH;
}

bool CrashpadReporter::SetCrashKey(base::StringPiece key,
                                   base::StringPiece value) {
  DCHECK_NE(reinterpret_cast<crashpad::SimpleStringDictionary*>(nullptr),
            crash_keys_.get());

  // StringPiece's aren't necessarily null terminated, so convert to
  // std::string first.
  std::string k = key.as_string();

  // SetKeyValue fails silently when the dictionary is full. If we're out of
  // entries fail if this is a new key.
  if (crash_keys_->GetCount() == crash_keys_->num_entries &&
      crash_keys_->GetValueForKey(k.c_str()) == nullptr) {
    return false;
  }

  // Set the key if there's room.
  std::string v = value.as_string();
  crash_keys_->SetKeyValue(k.c_str(), v.c_str());
  return true;
}

bool CrashpadReporter::SetMemoryRanges(const MemoryRanges& memory_ranges) {
  auto crashpad_info = crashpad::CrashpadInfo::GetCrashpadInfo();
  if (!crashpad_info)
    return false;

  // Create a local bag of address ranges and populate it.
  std::unique_ptr<crashpad::SimpleAddressRangeBag> ranges(
      new crashpad::SimpleAddressRangeBag());

  // Copy over as many ranges as will fit in the constrained
  // SimpleAddressRangeBag.
  size_t count = std::min(memory_ranges.size(), ranges->num_entries);
  for (size_t i = 0; i < count; ++i) {
    const auto& range = memory_ranges[i];
    ranges->Insert(crashpad::CheckedRange<uint64_t>(
        reinterpret_cast<uintptr_t>(range.first), range.second));
  }

  // Swap out the old bag for the new.
  crash_ranges_.reset(ranges.release());
  crashpad_info->set_extra_memory_ranges(crash_ranges_.get());

  // Return success only if all of the ranges were set.
  return count == memory_ranges.size();
}

bool CrashpadReporter::SetCustomStream(uint32_t stream_type,
                                       const uint8_t* stream_data,
                                       size_t stream_length) {
  auto crashpad_info = crashpad::CrashpadInfo::GetCrashpadInfo();
  if (!crashpad_info)
    return false;
  crashpad_info->AddUserDataMinidumpStream(
      stream_type, stream_data, stream_length);
  return true;
}

// Crashes the running process and sends a crash report.
void CrashpadReporter::DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) {
  g_crashpad_client.DumpAndCrash(exception_pointers);

  // The crash function shouldn't return, but putting a NOTREACHED here makes
  // this function difficult to test.
}

bool CrashpadReporter::DumpWithoutCrash(const CONTEXT& context) {
  g_crashpad_client.DumpWithoutCrash(context);
  return true;
}

CrashpadReporter::CrashpadReporter(crashpad::CrashpadInfo* crashpad_info)
    : crashpad_info_(crashpad_info) {
  crash_keys_.reset(new crashpad::SimpleStringDictionary());

  // Initialize the crashpad info struct. Limit indirectly referenced memory to
  // a maximum of 1MB, so that crash reports come in at around 1.5-1.7MB. This
  // is similar to the size of SyzyAsan crash reports generated by MS tools.
  crashpad_info->set_crashpad_handler_behavior(
      crashpad::TriState::kEnabled);
  crashpad_info->set_system_crash_reporter_forwarding(
      crashpad::TriState::kDisabled);
  crashpad_info->set_gather_indirectly_referenced_memory(
      crashpad::TriState::kEnabled, 1 * 1024 * 1024);
  crashpad_info->set_simple_annotations(crash_keys_.get());
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
