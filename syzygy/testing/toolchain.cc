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

#include "syzygy/testing/toolchain.h"

#include "base/environment.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"

namespace testing {

// This brings in auto-generated data in the form of macro definitions. It is
// included here to keep the scope as narrow as possible.
#include "syzygy/testing/toolchain_paths.gen"

const wchar_t kToolchainWrapperPath[] = TOOLCHAIN_WRAPPER_PATH;

// Undefine the macros brought in from toolchain_paths.gen.
#undef TOOLCHAIN_WRAPPER_PATH

}  // namespace testing
