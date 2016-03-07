// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_COMMON_ASSERTIONS_H_
#define SYZYGY_COMMON_ASSERTIONS_H_

#include <type_traits>

// Will cause compilation to fail if the given type is not a plain-old data
// type.
#define COMPILE_ASSERT_IS_POD(x) \
    static_assert(std::is_pod<x>::value, "Must be POD.")

// Causes compilation to fail if the given object is not a POD of a given size.
#define COMPILE_ASSERT_IS_POD_OF_SIZE(x, s) \
    static_assert(std::is_pod<x>::value && (sizeof(x) == s), \
                  "Must be a POD of " #s " bytes in size.")

#endif  // SYZYGY_COMMON_ASSERTIONS_H_
