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
// Declares the data structure that will be injected into Asan instrumented
// images and which contains instrumentation-time specified parameters to
// control the runtime. This allows for the specification of default parameters
// that aren't hard coded into the toolchain itself. Overrides may still be
// specified using the existing environment variable system.

#ifndef SYZYGY_COMMON_ASAN_PARAMETERS_H_
#define SYZYGY_COMMON_ASAN_PARAMETERS_H_

#include <set>
#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "syzygy/common/assertions.h"

namespace common {

#pragma pack(push, 1)

// The type used by stack IDs. This must be compatible with that used by
// the StackCaptureCache.
typedef uint32_t AsanStackId;

static const size_t kAsanParametersReserved1Bits = 19;

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
  uint32_t size;
  // The version number of this structure.
  uint32_t version;

  // The parameters should not change in size or offset. This structure should
  // be strictly added to, keeping it backwards compatible.

  // HeapProxy: The maximum size the quarantine may grow to, in bytes.
  uint32_t quarantine_size;
  // StackCaptureCache: The number of allocations between reports of the stack
  // trace cache compression ratio. A value of zero means no reports are
  // generated.
  uint32_t reporting_period;
  // StackCaptureCache: The number of bottom frames to skip on a stack trace.
  uint32_t bottom_frames_to_skip;
  // StackCapture: The max number of frames for a stack trace.
  uint32_t max_num_frames;
  // HeapProxy: The size of the padding added to every memory block trailer.
  uint32_t trailer_padding_size;
  // AsanRuntime: The stack ids we ignore, as a null terminated list. Set
  // this to NULL if there are no stack ids specified.
  AsanStackId* ignored_stack_ids;
  // HeapProxy: The maximum size of any single block that may be admitted to
  // the quarantine.
  uint32_t quarantine_block_size;

  // Bitfield of boolean values. When this bitfield is full add an entirely new
  // one at the end of the structure.
  union {
    uint32_t bitfield1;
    struct {
      // AsanLogger: If true, we should generate a minidump whenever an error is
      // detected.
      unsigned minidump_on_failure : 1;
      // Runtime: If we should stop the logger (and the running program)
      // after reporting an error.
      unsigned exit_on_failure : 1;
      // AsanLogger: If true, we should generate a textual log describing any
      // errors.
      unsigned log_as_text : 1;
      // Runtime: If true, we should check if the heap is corrupt on
      // failure.
      unsigned check_heap_on_failure : 1;
      // Runtime: If true, we won't try to report the crashes via breakpad
      // on failure.
      unsigned disable_breakpad_reporting : 1;
      // DEPRECATED: BlockHeapManager: Indicates if CtMalloc should be used to
      // serve the user's allocations.
      unsigned deprecated_enable_ctmalloc : 1;
      // ZebraBlockHeap: If true the ZebraBlockHeap will be used by the heap
      // manager.
      unsigned enable_zebra_block_heap : 1;
      // LargeBlockHeap: If true then the LargeBlockHeap will be used by the
      // heap manager.
      unsigned enable_large_block_heap : 1;
      // BlockHeapManager: Indicates if the allocation filtering is enabled. If
      // so, only blocks from filtered sites can make it into the zebra heap.
      unsigned enable_allocation_filter : 1;
      // Runtime: Indicates if the feature randomization is enabled.
      unsigned feature_randomization : 1;
      // BlockHeapManager: Indicates if we shouldn't report a crash for the same
      // corrupt block twice.
      unsigned prevent_duplicate_corruption_crashes : 1;
      // Runtime: Indicates if the invalid accesses should be reported.
      unsigned report_invalid_accesses : 1;
      // Runtime: Defer the crash reporter initialization, the client has to
      // manually call the crash reporter initialization function.
      unsigned defer_crash_reporter_initialization : 1;

      // Add new flags here!

      unsigned reserved1 : kAsanParametersReserved1Bits;
    };
  };

  // HeapProxy: The rate at which allocations are instrumented with header and
  // footer guards. This happens for each allocation via a runtime cointoss.
  // A value in the range 0.0 to 1.0, inclusive.
  float allocation_guard_rate;

  // ZebraBlockHeap: The size of the ZebraBlockHeap.
  uint32_t zebra_block_heap_size;

  // ZebraBlockHeap: The ratio of the memory used for the quarantine.
  float zebra_block_heap_quarantine_ratio;

  // LargeBlockHeap: The minimum size of allocations that will be passed to
  // the large block heap.
  uint32_t large_allocation_threshold;

  // The rate at which blocks will have their contents flood-filled upon entry
  // to the quarantine. When this occurs it encourages non-instrumented read-
  // after-frees to fail, and it also makes non-instrumented write-after-frees
  // plainly visible. A value in the range 0.0 to 1.0, inclusive. A value of
  // 0.0 corresponds to this being disabled entirely.
  float quarantine_flood_fill_rate;

  // Add new parameters here!

  // When laid out in memory the ignored_stack_ids are present here as a NULL
  // terminated vector.
};
#ifndef _WIN64
COMPILE_ASSERT_IS_POD_OF_SIZE(AsanParameters, 60);
#else
COMPILE_ASSERT_IS_POD_OF_SIZE(AsanParameters, 64);
#endif

// The current version of the Asan parameters structure. This must be updated
// if any changes are made to the above structure! This is defined in the header
// file to allow compile time assertions against this version number.
const uint32_t kAsanParametersVersion = 15;

// If the number of free bits in the parameters struct changes, then the
// version has to change as well. This is simply here to make sure that
// everything changes in lockstep.
static_assert(kAsanParametersReserved1Bits == 19 &&
                  kAsanParametersVersion == 15,
              "Version must change if reserved bits changes.");

// The name of the section that will be injected into an instrumented image,
// and contain the AsanParameters structure. Asan can't use your typical entry
// hook because the entry hook is called after the RTL has initialized itself.
// Instead the RTL scans through libraries in its memory and looks for a
// telltale section containing parameters. The first set of parameters it
// encounters are used. After that it may override some of them with environment
// variable configuration.
extern const char kAsanParametersSectionName[];
extern const uint32_t kAsanParametersSectionCharacteristics;

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
  const std::vector<uint8_t>& data() const { return data_; }
  const AsanParameters& params() const {
    return *reinterpret_cast<const AsanParameters*>(data_.data());
  }
  const AsanParameters* operator->() const {
    return reinterpret_cast<const AsanParameters*>(data_.data());
  }
  // @}

 protected:
  // The data backing the Asan parameters.
  std::vector<uint8_t> data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FlatAsanParameters);
};

// Default values of HeapProxy parameters
const uint32_t kDefaultQuarantineSize = 16 * 1024 * 1024;  // Exposed for tests.
extern const uint32_t kDefaultQuarantineBlockSize;
extern const uint32_t kDefaultTrailerPaddingSize;
extern const float kDefaultAllocationGuardRate;
// Default values of StackCaptureCache parameters.
extern const uint32_t kDefaultReportingPeriod;
extern const uint32_t kDefaultMaxNumFrames;
// Default values of StackCapture parameters.
extern const uint32_t kDefaultBottomFramesToSkip;
// Default values of AsanRuntime parameters.
extern const bool kDefaultExitOnFailure;
extern const bool kDefaultCheckHeapOnFailure;
extern const bool kDefaultDisableBreakpadReporting;
extern const bool kDefaultFeatureRandomization;
extern const bool kDefaultReportInvalidAccesses;
extern const bool kDefaultDeferCrashReporterInitialization;
// Default values of AsanLogger parameters.
extern const bool kDefaultMiniDumpOnFailure;
extern const bool kDefaultLogAsText;
// Default values of ZebraBlockHeap parameters.
extern const uint32_t kDefaultZebraBlockHeapSize;
extern const float kDefaultZebraBlockHeapQuarantineRatio;
// Default values of the BlockHeapManager parameters.
extern const bool kDefaultEnableZebraBlockHeap;
extern const bool kDefaultEnableAllocationFilter;
extern const float kDefaultQuarantineFloodFillRate;
extern const bool kDefaultPreventDuplicateCorruptionCrashes;
// Default values of LargeBlockHeap parameters.
extern const bool kDefaultEnableLargeBlockHeap;
extern const size_t kDefaultLargeAllocationThreshold;
extern const bool kDefaultEnableRateTargetedHeaps;

// The name of the environment variable containing the SyzyAsan command-line.
extern const char kSyzyAsanOptionsEnvVar[];

// The name of the command line variable containing the SyzyAsan RTL options.
extern const char kAsanRtlOptions[];

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
extern const char kParamFeatureRandomization[];
extern const char kParamReportInvalidAccesses[];
extern const char kParamDeferCrashReporterInitialization[];
// String names of AsanLogger parameters.
extern const char kParamMiniDumpOnFailure[];
extern const char kParamLogAsText[];
// String names of ZebraBlockHeap parameters.
extern const char kParamZebraBlockHeapSize[];
extern const char kParamZebraBlockHeapQuarantineRatio[];
// String names of BlockHeapManager parameters.
extern const char kParamDisableSizeTargetedHeaps[];
extern const char kParamEnableZebraBlockHeap[];
extern const char kParamEnableAllocationFilter[];
extern const char kParamQuarantineFloodFillRate[];
extern const char kParamPreventDuplicateCorruptionCrashes[];
// String names of LargeBlockHeap parameters.
extern const char kParamDisableLargeBlockHeap[];
extern const char kParamLargeAllocationThreshold[];

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
