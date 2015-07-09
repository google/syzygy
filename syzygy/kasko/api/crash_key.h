// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_KASKO_API_CRASH_KEY_H_
#define SYZYGY_KASKO_API_CRASH_KEY_H_

#include "base/strings/string16.h"

namespace kasko {
namespace api {

// Represents a property to include in a diagnostic report. This structure is
// intended to have the same layout as a google_breakpad::CustomInfoEntry to
// facilitate maintenance of a single property store in clients.
struct CrashKey {
  // Maximum name length.
  static const int kNameMaxLength = 64;
  // Maximum value length.
  static const int kValueMaxLength = 64;

  // The name of the property.
  base::char16 name[kNameMaxLength];
  // The value of the property.
  base::char16 value[kValueMaxLength];
};

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_CRASH_KEY_H_
