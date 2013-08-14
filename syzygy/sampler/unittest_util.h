// Copyright 2013 Google Inc. All Rights Reserved.
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
// Utilities for generating sampling profiler test data.

#ifndef SYZYGY_SAMPLER_UNITTEST_UTIL_H_
#define SYZYGY_SAMPLER_UNITTEST_UTIL_H_

#include "base/files/file_path.h"

namespace testing {

// Generates a dummy trace file for test_dll.dll, containing nothing but a
// single sampling profiler record. Causes an assertion on failure. Should be
// called via ASSERT_NO_FATAL_FAILURE.
// @param path The path where the trace file should be written.
void WriteDummySamplerTraceFile(const base::FilePath& path);

}  // namespace testing

#endif  // SYZYGY_SAMPLER_UNITTEST_UTIL_H_
