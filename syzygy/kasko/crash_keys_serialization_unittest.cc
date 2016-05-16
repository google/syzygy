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

#include <map>
#include <memory>

#include "base/values.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/string16.h"
#include "gtest/gtest.h"

namespace kasko {

TEST(CrashKeysSerializationTest, BasicTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_file = temp_dir.path().Append(L"test.dat");
  std::map<base::string16, base::string16> crash_keys;
  crash_keys[L"name"] = L"value";
  ASSERT_TRUE(WriteCrashKeysToFile(temp_file, crash_keys));
  std::map<base::string16, base::string16> crash_keys_from_disk;
  ASSERT_TRUE(ReadCrashKeysFromFile(temp_file, &crash_keys_from_disk));
  ASSERT_EQ(crash_keys, crash_keys_from_disk);
}

TEST(CrashKeysSerializationTest, MissingFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  std::map<base::string16, base::string16> crash_keys_from_disk;
  ASSERT_FALSE(ReadCrashKeysFromFile(
      temp_dir.path().Append(L"some_other_path.dat"), &crash_keys_from_disk));
}

TEST(CrashKeysSerializationTest, InvalidFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_file = temp_dir.path().Append(L"test.dat");
  std::string invalid_file_contents =
      "These aren't the bytes you're looking for.";
  ASSERT_TRUE(base::WriteFile(temp_file, invalid_file_contents.data(),
                              invalid_file_contents.length()));
  std::map<base::string16, base::string16> crash_keys_from_disk;
  ASSERT_FALSE(ReadCrashKeysFromFile(temp_file, &crash_keys_from_disk));
}

TEST(CrashKeysSerializationTest, IllegalDictionaryContents) {
  base::DictionaryValue dictionary;
  std::unique_ptr<base::ListValue> list(new base::ListValue);
  list->AppendString("value 1");
  dictionary.Set("name", list.release());
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_file = temp_dir.path().Append(L"test.dat");
  std::string file_contents;
  ASSERT_TRUE(base::JSONWriter::Write(dictionary, &file_contents));
  ASSERT_TRUE(
      base::WriteFile(temp_file, file_contents.data(), file_contents.length()));
  std::map<base::string16, base::string16> crash_keys_from_disk;
  ASSERT_FALSE(ReadCrashKeysFromFile(temp_file, &crash_keys_from_disk));
}

TEST(CrashKeysSerializationTest, NotADictionary) {
  base::ListValue list;
  list.AppendString("value 1");
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_file = temp_dir.path().Append(L"test.dat");
  std::string file_contents;
  ASSERT_TRUE(base::JSONWriter::Write(list, &file_contents));
  ASSERT_TRUE(
      base::WriteFile(temp_file, file_contents.data(), file_contents.length()));
  std::map<base::string16, base::string16> crash_keys_from_disk;
  ASSERT_FALSE(ReadCrashKeysFromFile(temp_file, &crash_keys_from_disk));
}

}  // namespace kasko
