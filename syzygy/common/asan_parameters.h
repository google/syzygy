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
// Declares the data structure that will be injected into ASAN instrumented
// images and which contains instrumentation-time specified parameters to
// control the runtime. This allows for the specification of default parameters
// that aren't hard coded into the toolchain itself. Overrides may still be
// specified using the existing environment variable system.

#ifndef SYZYGY_COMMON_ASAN_PARAMETERS_H_
#define SYZYGY_COMMON_ASAN_PARAMETERS_H_

#include <set>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/string_piece.h"
#include "syzygy/common/assertions.h"

namespace common {

#pragma pack(push, 1)

// The type used by stack IDs. This must be compatible with that used by
// the StackCaptureCache.
typedef uint32 AsanStackId;

// This data structure is injected into an instrumented image in a read-only
// section. It is initialized by the instrumenter, and will be looked up at
// runtime by the SyzyAsan RTL. Values in this structure (if present) will
// override hard-coded default values. Values in this structure may be
// superceded by environment variable parameter settings.
struct AsanParameters {
  // The first two members of this structure are fixed, and must always be
  // present. This allows for the detection of version shear between RTLs and
  // instrumented code.

  // The overall size of the structure. This should include the total size of
  // any variable sized data included at the end of this structure as laid out
  // in an image.
  uint32 size;
  // The version number of this structure.
  uint32 version;

  // The parameters should not change in size or offset. This structure should
  // be strictly added to, keeping it backwards compatible.

  // HeapProxy: The maximum size the quarantine may grow to, in bytes.
  uint32 quarantine_size;
  // StackCaptureCache: The number of allocations between reports of the stack
  // trace cache compression ratio. A value of zero means no reports are
  // generated.
  uint32 reporting_period;
  // StackCaptureCache: The number of bottom frames to skip on a stack trace.
  uint32 bottom_frames_to_skip;
  // StackCapture: The max number of frames for a stack trace.
  uint32 max_num_frames;
  // HeapProxy: The size of the padding added to every memory block trailer.
  uint32 trailer_padding_size;
  // AsanRuntime: The stack ids we ignore, as a null terminated list. Set
  // this to NULL if there are no stack ids specified.
  AsanStackId* ignored_stack_ids;
  // HeapProxy: The maximum size of any single block that may be admitted to
  // the quarantine.
  uint32 quarantine_block_size;

  // Bitfield of boolean values. When this bitfield is full add an entirely new
  // one at the end of the structure.
  union {
    uint32 bitfield1;
    struct {
      // AsanLogger: If true, we should generate a minidump whenever an error is
      // detected.
      unsigned minidump_on_failure : 1;
      // AsanRuntime: If we should stop the logger (and the running program)
      // after reporting an error.
      unsigned exit_on_failure : 1;
      // AsanLogger: If true, we should generate a textual log describing any
      // errors.
      unsigned log_as_text : 1;
      // AsanRuntime: If true, we should check if the heap is corrupt on
      // failure.
      unsigned check_heap_on_failure : 1;
      // AsanRuntime: If true, we won't try to report the crashes via breakpad
      // on failure.
      unsigned disable_breakpad_reporting : 1;

      // Add new flags here!

      unsigned reserved1 : 27;
    };
  };

  // HeapProxy: The rate at which allocations are instrumented with header and
  // footer guards. This happens for each allocation via a runtime cointoss.
  // A value in the range 0.0 to 1.0, inclusive.
  float allocation_guard_rate;

  // ZebraBlockHeap: The size of the ZebraBlockHeap.
  uint32 zebra_block_heap_size;

  // Add new parameters here!

  // When laid out in memory the ignored_stack_ids are present here as a NULL
  // terminated vector.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(AsanParameters, 48);

// The current version of the ASAN parameters structure. This must be updated
// if any changes are made to the above structure! This is defined in the header
// file to allow compile time assertions against this version number.
const uint32 kAsanParametersVersion = 2u;

// The name of the section that will be injected into an instrumented image,
// and contain the AsanParameters structure. ASAN can't use your typical entry
// hook because the entry hook is called after the RTL has initialized itself.
// Instead the RTL scans through libraries in its memory and looks for a
// telltale section containing parameters. The first set of parameters it
// encounters are used. After that it may override some of them with environment
// variable configuration.
extern const char kAsanParametersSectionName[];
extern const uint32 kAsanParametersSectionCharacteristics;

#pragma pack(pop)

// An inflated version of AsanParameters for dynamically parsing into. This can
// then be flattened into a FlatAsanParameters object. In this representation
// variable sized fields of the flat representation are backed by STL
// containers.
struct InflatedAsanParameters : public AsanParameters {
  InflatedAsanParameters();

  std::set<AsanStackId> ignored_stack_ids_set;

 protected:
  // Deprecate use of this field in favour of the STL set version.
  using AsanParameters::ignored_stack_ids;
};

// A flat version of AsanParameters, backed by a vector for housing the variable
// sized data. This is a read-only structure.
class FlatAsanParameters {
 public:
  // Constructs a flat parameter representation from the given set of parsed
  // parameters.
  explicit FlatAsanParameters(const InflatedAsanParameters& asan_parameters);

  // @name Accessors.
  // @{
  const std::vector<uint8>& data() const { return data_; }
  const AsanParameters& params() const {
    return *reinterpret_cast<const AsanParameters*>(data_.data());
  }
  const AsanParameters* operator->() const {
    return reinterpret_cast<const AsanParameters*>(data_.data());
  }
  // @}

 protected:
  // The data backing the ASAN parameters.
  std::vector<uint8> data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FlatAsanParameters);
};

// Default values of HeapProxy parameters
extern const uint32 kDefaultQuarantineSize;
extern const uint32 kDefaultQuarantineBlockSize;
extern const uint32 kDefaultTrailerPaddingSize;
extern const float kDefaultAllocationGuardRate;
// Default values of StackCaptureCache parameters.
extern const uint32 kDefaultReportingPeriod;
extern const uint32 kDefaultMaxNumFrames;
// Default values of StackCapture parameters.
extern const uint32 kDefaultBottomFramesToSkip;
// Default values of AsanRuntime parameters.
extern const bool kDefaultExitOnFailure;
extern const bool kDefaultCheckHeapOnFailure;
extern const bool kDefaultDisableBreakpadReporting;
// Default values of AsanLogger parameters.
extern const bool kDefaultMiniDumpOnFailure;
extern const bool kDefaultLogAsText;
// Default values of ZebraBlockHeap parameters.
extern const uint32 kDefaultZebraBlockHeapSize;

// String names of HeapProxy parameters.
extern const char kParamQuarantineSize[];
extern const char kParamQuarantineBlockSize[];
extern const char kParamTrailerPaddingSize[];
extern const char kParamAllocationGuardRate[];
// String names of StackCaptureCache parameters.
extern const char kParamReportingPeriod[];
extern const char kParamBottomFramesToSkip[];
// String names of StackCapture parameters.
extern const char kParamMaxNumFrames[];
// String names of AsanRuntime parameters.
extern const char kParamIgnoredStackIds[];
extern const char kParamExitOnFailure[];
extern const char kParamDisableBreakpadReporting[];
// String names of AsanLogger parameters.
extern const char kParamMiniDumpOnFailure[];
extern const char kParamLogAsText[];
// String names of ZebraHeapZize parameters.
extern const char kParamZebraBlockHeapSize[];

// Initializes an AsanParameters struct with default values.
// @param asan_parameters The AsanParameters struct to be initialized.
void SetDefaultAsanParameters(AsanParameters* asan_parameters);

// Initializes an InflatedAsanParameters from a FlatAsanParameters.
// @param params The POD asan parameters to copy.
// @param inflated_params The inflated parameters to be populated.
bool InflateAsanParameters(const AsanParameters* pod_params,
                           InflatedAsanParameters* inflated_params);

// Parses parameters from a string, and updates the provided structure.
// @param param_string the string of parameters to be parsed.
// @param asan_parameters The AsanParameters struct to be updated.
// @returns true on success, false otherwise. Logs verbosely on failure.
bool ParseAsanParameters(const base::StringPiece16& param_string,
                         InflatedAsanParameters* asan_parameters);

}  // namespace common

#endif  // SYZYGY_COMMON_ASAN_PARAMETERS_H_
