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

#ifndef SYZYGY_KASKO_CRASH_KEYS_SERIALIZATION_H_
#define SYZYGY_KASKO_CRASH_KEYS_SERIALIZATION_H_

#include <map>
#include "base/strings/string16.h"

namespace base {
class FilePath;
}  // namespace base

namespace kasko {

// Reads serialized crash keys.
// @param file_path The file to read from.
// @param crash_keys A map to store the deserialized crash keys in.
// @returns true if the operation succeeds.
bool ReadCrashKeysFromFile(
    const base::FilePath& file_path,
    std::map<base::string16, base::string16>* crash_keys);

// Writes serialized crash keys.
// @param file_path The file to write to.
// @param crash_keys The crash keys to write.
// @returns true if the operation succeeds.
bool WriteCrashKeysToFile(
    const base::FilePath& file_path,
    const std::map<base::string16, base::string16>& crash_keys);

}  // namespace kasko

#endif  // SYZYGY_KASKO_CRASH_KEYS_SERIALIZATION_H_
