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

#ifndef SYZYGY_AGENT_ASAN_REPORTERS_KASKO_REPORTER_H_
#define SYZYGY_AGENT_ASAN_REPORTERS_KASKO_REPORTER_H_

#include <windows.h>

#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/reporter.h"
#include "syzygy/agent/asan/reporters/exported_function.h"

namespace agent {
namespace asan {
namespace reporters {

// Implements Kasko crash reporting integration.
class KaskoReporter : ReporterInterface {
 public:
  // Exported functions that are used for Kasko crash reporting integration.
  using ReportCrashWithProtobuf = ExportedFunction<
      void __cdecl(EXCEPTION_POINTERS* info,
                   const char* protobuf,
                   size_t protobuf_length)>;
  using ReportCrashWithProtobufAndMemoryRanges = ExportedFunction<
      void __cdecl(EXCEPTION_POINTERS* info,
                   const char* protobuf,
                   size_t protobuf_length,
                   const void* const* base_addresses,
                   const size_t* lengths)>;
  using SetCrashKeyValueImpl = ExportedFunction<
      void __cdecl(const wchar_t* key, const wchar_t* value)>;

  // Expected Kasko crash reporter functions. This allows functions
  // to be injected for testing.
  struct KaskoFunctions {
    ReportCrashWithProtobuf report_crash_with_protobuf;
    ReportCrashWithProtobufAndMemoryRanges
        report_crash_with_protobuf_and_memory_ranges;
    SetCrashKeyValueImpl set_crash_key_value_impl;
  };

  // Factory for a KaskoReporter. This returns null if the running process
  // does not support Kasko crash reporting. Support is decided by examining
  // the exports of the running executable, and looking for Kasko's expected
  // exports.
  // @returns an allocated KaskoReporter
  static scoped_ptr<KaskoReporter> Create();

  // Helper to determine if a given set of functions is valid.
  // @param kasko_functions The functions to evaluate.
  // @returns true on success, false otherwise.
  static bool AreValid(const KaskoFunctions& kasko_functions);

  // Constructor with specified functions.
  explicit KaskoReporter(const KaskoFunctions& kasko_functions)
      : kasko_functions_(kasko_functions) {
    DCHECK(AreValid(kasko_functions_));
  }

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

 protected:
  friend class KaskoReporterTest;

  // Returns true if the instrumented application supports early crash keys.
  // Visible for testing.
  static bool SupportsEarlyCrashKeys();

  // The kasko functions to use.
  KaskoFunctions kasko_functions_;

  // Memory ranges set by SetMemoryRanges. These are unfolded into the format
  // expected by Kasko.
  std::vector<const void*> range_bases_;
  std::vector<size_t> range_lengths_;

  // Stores the serialized crash data protobuf to be added to the crash report.
  // Set by SetCustomStream, but if and only if called with |stream_type| ==
  // kCrashdataProtobufStreamType.
  std::string protobuf_;

 private:
  DISALLOW_COPY_AND_ASSIGN(KaskoReporter);
};

}  // namespace reporters
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REPORTERS_KASKO_REPORTER_H_
