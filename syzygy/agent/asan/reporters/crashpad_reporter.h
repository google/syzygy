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

#ifndef SYZYGY_AGENT_ASAN_REPORTERS_CRASHPAD_REPORTER_H_
#define SYZYGY_AGENT_ASAN_REPORTERS_CRASHPAD_REPORTER_H_

#include <windows.h>
#include <memory>

#include "base/callback.h"
#include "client/crashpad_info.h"
#include "syzygy/agent/asan/reporter.h"

namespace agent {
namespace asan {
namespace reporters {

// Implements Crashpad crash reporting integration. Use of this class is not
// thread safe.
class CrashpadReporter : public ReporterInterface {
 public:
  // The name of this reporter, as returned by GetName.
  static const char kName[];

  // Factory for a CrashpadReporter. This returns null if the running process
  // does not support Crashpad crash reporting. Support is decided by examining
  // the exports of the running executable, and looking for Crashpad's expected
  // exports.
  // @returns an allocated CrashpadReporter
  static std::unique_ptr<CrashpadReporter> Create();

  virtual ~CrashpadReporter() {}

  // @name ReporterInterface implementation.
  // @{
  const char* GetName() const override;
  uint32_t GetFeatures() const override;
  // This can fail when the underlying Crashpad dictionary is full.
  bool SetCrashKey(base::StringPiece key, base::StringPiece value) override;
  // This can fail if the underlying Crashpad struct is full. Even when it
  // fails it will have stored as many memory_ranges as possible.
  bool SetMemoryRanges(const MemoryRanges& memory_ranges) override;
  // NOTE: This should only be called once for a given stream ID, as Crashpad
  // doesn't allow overwriting. Calling repeatedly with the same ID will
  // currently cause the Crashpad minidump writer to explode.
  bool SetCustomStream(uint32_t stream_type,
                       const uint8_t* stream_data,
                       size_t stream_length) override;
  void DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) override;
  bool DumpWithoutCrash(const CONTEXT& context) override;
  // @}

 private:
  friend class CrashpadReporterTest;

  explicit CrashpadReporter(crashpad::CrashpadInfo* crashpad_info);

  crashpad::CrashpadInfo* crashpad_info_;
  std::unique_ptr<crashpad::SimpleAddressRangeBag> crash_ranges_;
  std::unique_ptr<crashpad::SimpleStringDictionary> crash_keys_;

  DISALLOW_COPY_AND_ASSIGN(CrashpadReporter);
};

}  // namespace reporters
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REPORTERS_CRASHPAD_REPORTER_H_
