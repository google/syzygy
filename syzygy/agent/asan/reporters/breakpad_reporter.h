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

#ifndef SYZYGY_AGENT_ASAN_REPORTERS_BREAKPAD_REPORTER_H_
#define SYZYGY_AGENT_ASAN_REPORTERS_BREAKPAD_REPORTER_H_

#include <windows.h>
#include <memory>

#include "syzygy/agent/asan/reporter.h"
#include "syzygy/agent/asan/reporters/exported_function.h"

namespace agent {
namespace asan {
namespace reporters {

// Implements Breakpad crash reporting integration.
class BreakpadReporter : public ReporterInterface {
 public:
  // The main crash inducing function that Breakpad exports.
  using CrashForException = ExportedFunction<
      int __cdecl(EXCEPTION_POINTERS* info)>;
  // Signatures of Breakpad-related functions for setting crash keys. This
  // API has evolved over time, so multiple signatures are supported.
  // Post r194002.
  using SetCrashKeyValuePair = ExportedFunction<
      void __cdecl(const char* key, const char* value)>;
  // Post r217590.
  using SetCrashKeyValueImpl = ExportedFunction<
      void __cdecl(const wchar_t* key, const wchar_t* value)>;

  // Expected Breakpad crash reporter functions. This allows functions
  // to be injected for testing.
  struct BreakpadFunctions {
    CrashForException crash_for_exception;
    SetCrashKeyValuePair set_crash_key_value_pair;
    SetCrashKeyValueImpl set_crash_key_value_impl;
  };

  // Factory for a BreakpadReporter. This returns null if the running process
  // does not support Breakpad crash reporting. Support is decided by examining
  // the exports of the running executable, and looking for Breakpad's expected
  // exports.
  // @returns an allocated BreakpadReporter
  static std::unique_ptr<BreakpadReporter> Create();

  // Helper to determine if a given set of functions is valid.
  // @param breakpad_functions The functions to evaluate.
  // @returns true on success, false otherwise.
  static bool AreValid(const BreakpadFunctions& breakpad_functions);

  // Constructor with specified functions.
  explicit BreakpadReporter(const BreakpadFunctions& breakpad_functions)
      : breakpad_functions_(breakpad_functions) {
    DCHECK(AreValid(breakpad_functions_));
  }

  virtual ~BreakpadReporter() {}

  // @name ReporterInterface implementation.
  // @{
  const char* GetName() const override;
  uint32_t GetFeatures() const override;
  bool SetCrashKey(base::StringPiece key, base::StringPiece value) override;
  bool SetMemoryRanges(const MemoryRanges& memory_ranges) override;
  bool SetCustomStream(uint32_t stream_type,
                       const uint8_t* stream_data,
                       size_t stream_length) override;
  void DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) override;
  bool DumpWithoutCrash(const CONTEXT& context) override;
  // @}

 private:
  // The breakpad functions to use.
  BreakpadFunctions breakpad_functions_;

  DISALLOW_COPY_AND_ASSIGN(BreakpadReporter);
};

}  // namespace reporters
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REPORTERS_BREAKPAD_REPORTER_H_
