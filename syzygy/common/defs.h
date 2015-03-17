// Copyright 2011 Google Inc. All Rights Reserved.
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
// Common definitions and constants for the Syzygy toolchain.

#ifndef SYZYGY_COMMON_DEFS_H_
#define SYZYGY_COMMON_DEFS_H_

namespace common {

// This is the name of the section that will be created by hot patching
// transformations. It contains metadata that is required for hot patching
// at runtime.
extern const char kHotPatchingMetadataSectionName[];

// This is the name of the section that will be created in modules that
// are produced by the Syzygy toolchain. It contains metadata that allows
// for consistency checking between the various parts of the toolchain.
extern const char kSyzygyMetadataSectionName[];

// Stores the name that is associated with resource sections.
extern const char kResourceSectionName[];

// Stores the name that is commonly associated with thunk sections.
extern const char kThunkSectionName[];

// We add this suffix to the thunk blocks created by the toolchain.
extern const char kThunkSuffix[];

}  // namespace common

#endif  // SYZYGY_COMMON_DEFS_H_
