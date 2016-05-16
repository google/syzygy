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

#include "syzygy/agent/asan/reporters/breakpad_reporter.h"

#include "base/strings/utf_string_conversions.h"

namespace agent {
namespace asan {

// Define required export names.
const char* reporters::BreakpadReporter::CrashForException::name_ =
    "CrashForException";
const char* reporters::BreakpadReporter::SetCrashKeyValuePair::name_ =
    "SetCrashKeyValuePair";
const char* reporters::BreakpadReporter:: SetCrashKeyValueImpl::name_ =
    "SetCrashKeyValueImpl";

namespace reporters {

// static
std::unique_ptr<BreakpadReporter> BreakpadReporter::Create() {
  // Initialize the required reporter functions
  BreakpadFunctions breakpad_functions;
  breakpad_functions.crash_for_exception.Lookup();
  breakpad_functions.set_crash_key_value_pair.Lookup();
  breakpad_functions.set_crash_key_value_impl.Lookup();
  if (!AreValid(breakpad_functions))
    return nullptr;

  return std::unique_ptr<BreakpadReporter>(
      new BreakpadReporter(breakpad_functions));
}

// static
bool BreakpadReporter::AreValid(const BreakpadFunctions& breakpad_functions) {
  // The crash function and exactly one crash key reporting function must be
  // present.
  if (!breakpad_functions.crash_for_exception.IsValid())
    return false;
  if (breakpad_functions.set_crash_key_value_pair.IsValid() ==
      breakpad_functions.set_crash_key_value_impl.IsValid()) {
    return false;
  }
  return true;
}

const char* BreakpadReporter::GetName() const {
  return "BreakpadReporter";
}

uint32_t BreakpadReporter::GetFeatures() const {
  return FEATURE_CRASH_KEYS;
}

bool BreakpadReporter::SetCrashKey(base::StringPiece key,
                                   base::StringPiece value) {
  // Only one of the functions should be set.
  DCHECK_NE(breakpad_functions_.set_crash_key_value_pair.IsValid(),
            breakpad_functions_.set_crash_key_value_impl.IsValid());

  // The 'Impl' variant is the more recent of the two, so check it first.
  if (breakpad_functions_.set_crash_key_value_impl.IsValid()) {
    std::wstring wkey = base::UTF8ToWide(key);
    std::wstring wvalue = base::UTF8ToWide(value);
    breakpad_functions_.set_crash_key_value_impl.Run(
        wkey.c_str(), wvalue.c_str());
  } else {
    DCHECK(breakpad_functions_.set_crash_key_value_pair.IsValid());
    // StringPiece objects aren't necessarily null terminated, so copy them to
    // strings to be sure they'll be terminated properly.
    std::string skey(key.as_string());
    std::string svalue(value.as_string());
    breakpad_functions_.set_crash_key_value_pair.Run(
        skey.c_str(), svalue.c_str());
  }
  return true;
}

bool BreakpadReporter::SetMemoryRanges(const MemoryRanges& memory_ranges) {
  // Unsupported.
  return false;
}

bool BreakpadReporter::SetCustomStream(uint32_t stream_type,
                                       const uint8_t* stream_data,
                                       size_t stream_length) {
  // Unsupported.
  return false;
}

// Crashes the running process and sends a crash report.
void BreakpadReporter::DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) {
  DCHECK(breakpad_functions_.crash_for_exception.IsValid());
  breakpad_functions_.crash_for_exception.Run(exception_pointers);

  // The crash function shouldn't return, but putting a NOTREACHED here makes
  // this function difficult to test.
}

bool BreakpadReporter::DumpWithoutCrash(const CONTEXT& context) {
  // Unsupported.
  return false;
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
