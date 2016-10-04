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
//
// This class abstracts away various different crash reporting systems that
// SyzyASan is able to interact with.

#ifndef SYZYGY_AGENT_ASAN_REPORTER_H_
#define SYZYGY_AGENT_ASAN_REPORTER_H_

#include <cstdint>
#include <utility>
#include <vector>

#include "base/strings/string_piece.h"

namespace agent {
namespace asan {

// Interface for a crash reporter.
class ReporterInterface {
 public:
  // This is the stream type defined to hold the Crashdata protobuf.
  enum : uint32_t { kCrashdataProtobufStreamType = 0x4B6B0001 };

  // An enumeration of the features supported by this crash reporter. This
  // is a bitmask.
  enum Features : uint32_t {
    // Supports a crash keys metadata mechanism.
    FEATURE_CRASH_KEYS = (1 << 0),

    // Supports crash keys that can be set during RTL initialization, ie.
    // under the loader's lock.
    FEATURE_EARLY_CRASH_KEYS = (1 << 1),

    // Supports memory ranges.
    FEATURE_MEMORY_RANGES = (1 << 2),

    // Supports custom minidump streams.
    FEATURE_CUSTOM_STREAMS = (1 << 3),

    // Supports reporting without crashing.
    FEATURE_DUMP_WITHOUT_CRASH = (1 << 4),
  };

  // A memory range is expressed as a pointer and a length.
  using MemoryRange = std::pair<const char*, size_t>;
  using MemoryRanges = std::vector<MemoryRange>;

  ReporterInterface() {}
  virtual ~ReporterInterface() {}

  // @returns the name of this crash reporter.
  virtual const char* GetName() const = 0;

  // @returns the feature set of this crash reporter.
  virtual uint32_t GetFeatures() const = 0;

  // Sets a crash key. This may fail if crash keys are unsupported by the
  // crash reporter, or if the crash keys are otherwise invalid. The definition
  // of invalid depends on the reporter implementation.
  // @param key The crash key.
  // @param value The crash key value.
  // @returns true on success, false otherwise.
  virtual bool SetCrashKey(base::StringPiece key,
                           base::StringPiece value) = 0;

  // Sets a bag of memory ranges to be included in a crash report. This may
  // fail if the underlying crash reporter doesn't support the mechanism. This
  // has override semantics, so calling this will replace the values stored
  // in any previous calls.
  // @param memory_ranges The memory ranges to include in the report.
  // @returns true on success, false otherwise.
  virtual bool SetMemoryRanges(const MemoryRanges& memory_ranges) = 0;

  // Sets a custom stream to include with a crash report. For a given
  // @p stream_type this has override semantics. To erase a given stream
  // call this with nullptr @p stream_data and @p stream_length of zero.
  // @param stream_type The type of the stream to add. This should normally
  //     be larger than MINIDUMP_STREAM_TYPE::LastReservedStream, which is
  //     0xFFFF.
  // @param stream_data A pointer to the stream data. This is owned by the
  //     caller and must remain valid forever after being added.
  // @param stream_length The length of the stream.
  // @returns true on success, false otherwise.
  virtual bool SetCustomStream(uint32_t stream_type,
                               const uint8_t* stream_data,
                               size_t stream_length) = 0;

  // Crashes the running process and sends a crash report. This function
  // should not return, so users should follow it with a NOTREACHED to
  // ensure safety.
  // @param exception_pointers The exception pointers to use in the crash.
  virtual void DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) = 0;

  // Generates a crash report, but continues running and returns.
  // @param context The context to use in the crash report.
  // @param returns true on success, false otherwise.
  virtual bool DumpWithoutCrash(const CONTEXT& context) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(ReporterInterface);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REPORTER_H_
