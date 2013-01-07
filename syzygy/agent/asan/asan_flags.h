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
//
// Defines a flags manager for asan. It provides the function to read the flags
// from the corresponding environment variable.

#ifndef SYZYGY_AGENT_ASAN_ASAN_FLAGS_H_
#define SYZYGY_AGENT_ASAN_ASAN_FLAGS_H_

#include "base/lazy_instance.h"
#include "base/string_piece.h"

namespace agent {
namespace asan {

// A singleton class that takes care of initializing asan flags.
class FlagsManager {
 public:
  // Retrieves the flags manager singleton instance.
  static FlagsManager* Instance();

  // Initialize the flags with the environment variable.
  bool InitializeFlagsWithEnvVar();

 protected:
  // Make sure the LazyInstance can be created.
  friend struct base::DefaultLazyInstanceTraits<FlagsManager>;

  FlagsManager();
  ~FlagsManager();

  // The name of the environment variable containing the command-line.
  static const char kSyzyAsanEnvVar[];

  // @name Flag strings.
  // @{
  static const char kQuarantineSize[];
  static const char kCompressionReportingPeriod[];
  // @}

  // Parse and set the flags from the wide string @p str.
  bool ParseFlagsFromString(const std::wstring& str);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_FLAGS_H_
