// Copyright 2012 Google Inc.
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
// Declares data structures and constants used by the various pieces of the code
// coverage client and instrumentation.

#ifndef SYZYGY_COMMON_COVERAGE_H_
#define SYZYGY_COMMON_COVERAGE_H_

#include <windows.h>

#include "base/basictypes.h"

namespace common {

// This data structure is injected into an instrumented image in a read-write
// section of its own. It will be initialized by the runtime client library
// and is referred to by all of the instrumentation code.
struct CoverageData {
  // A signature used to verify that the module was instrumented by a valid
  // coverage client.
  uint32 magic;

  // The version of the client library that instrumented the binary. If this
  // doesn't match the running client library then the whole process should be
  // aborted.
  uint32 version;

  // Code coverage uses a single process wide basic block array, thus only needs
  // to be initialized once. Our hooks grab various other entry points
  // (including TLS constructors/destructors), so the initialization routine may
  // be called repeatedly. We use this to determine whether or not we should try
  // initializing things. Upon first entry this is protected by the loader lock
  // and afterwards it is only read, so synchronization is not an issue.
  uint32 initialization_attempted;

  // The number of basic blocks in the instrumented image. This is required by
  // the runtime client library so it knows how big an array to allocate.
  uint32 basic_block_count;

  // This points to an array of length 'basic_block_count'. At linktime it is
  // initialized to point to an array that is in the .data section of the image
  // (this is done so that if capture is not enabled the binary can still run
  // without crashing). At runtime the client library will allocate a call-trace
  // buffer and redirect this pointer to point to it.
  uint8* basic_block_seen_array;
};

// The coverage client 'magic'.
extern const uint32 kCoverageClientMagic;

// The coverage client version.
extern const uint32 kCoverageClientVersion;

// This is the name of the data section added to an instrumented image by
// the coverage client.
extern const char kCoverageClientDataSectionName[];

// The characteristics given to the coverage instrumentation section.
extern const DWORD kCoverageClientDataSectionCharacteristics;

// The name of the basic-block addresses stream added to the PDB by the
// coverage instrumentation.
extern const char kCoverageAddressesStreamName[];

}  // namespace common

#endif  // SYZYGY_COMMON_COVERAGE_H_
