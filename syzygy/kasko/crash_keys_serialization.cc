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

#include "syzygy/kasko/crash_keys_serialization.h"

#include <memory>

#include "base/logging.h"
#include "base/values.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/utf_string_conversions.h"

namespace kasko {

bool ReadCrashKeysFromFile(
    const base::FilePath& file_path,
    std::map<base::string16, base::string16>* crash_keys) {
  DCHECK(crash_keys);
  std::string file_contents;
  if (!base::ReadFileToString(file_path, &file_contents)) {
    LOG(ERROR) << "Failed to read crash keys from file " << file_path.value();
    return false;
  }

  std::unique_ptr<base::Value> value(
      base::JSONReader::Read(file_contents).release());
  base::DictionaryValue* dictionary = nullptr;
  if (!value || !value->GetAsDictionary(&dictionary)) {
    LOG(ERROR) << "The crash keys file contents from " << file_path.value()
               << " are not a valid JSON dictionary:\n" << file_contents;
    return false;
  }

  for (base::DictionaryValue::Iterator it(*dictionary); !it.IsAtEnd();
       it.Advance()) {
    base::string16 value;
    if (!it.value().GetAsString(&value)) {
      LOG(ERROR) << "The crash keys file contents from " << file_path.value()
                 << " contain an invalid value for entry " << it.key()
                 << ". File Contents:\n" << file_contents;
      return false;
    }
    crash_keys->insert(std::make_pair(base::UTF8ToWide(it.key()), value));
  }
  return true;
}

bool WriteCrashKeysToFile(
    const base::FilePath& file_path,
    const std::map<base::string16, base::string16>& crash_keys) {
  base::DictionaryValue dictionary;
  for (const auto& entry : crash_keys) {
    dictionary.SetStringWithoutPathExpansion(base::WideToUTF8(entry.first),
                                             base::WideToUTF8(entry.second));
  }

  std::string file_contents;
  if (!base::JSONWriter::Write(dictionary, &file_contents)) {
    LOG(ERROR) << "Failed to serialize crash keys.";
    return false;
  }

  if (!base::WriteFile(file_path, file_contents.data(),
                       file_contents.length())) {
    LOG(ERROR) << "Failed to write serialized crash keys to "
               << file_path.value();
    return false;
  }

  return true;
}

}  // namespace kasko
