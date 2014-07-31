// Copyright 2009 Google Inc.
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
// Preference reader/writer class implementation.
#include "sawbuck/viewer/preferences.h"

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/utf_string_conversions.h"
#include "sawbuck/viewer/const_config.h"

Preferences::Preferences() {
}

bool Preferences::WriteStringValue(const wchar_t* name,
                                   const std::wstring& value) {
  if (!EnsureWritableKey())
    return false;

  LONG err = key_.SetStringValue(name, value.c_str());
  return err == ERROR_SUCCESS;
}

bool Preferences::WriteStringValue(const wchar_t* name,
                                   const std::string& value) {
  return WriteStringValue(name, base::UTF8ToWide(value));
}

bool Preferences::ReadStringValue(const wchar_t* name,
                                  std::wstring* value,
                                  const wchar_t* default_value) {
  DCHECK(value != NULL);

  if (EnsureReadableKey()) {
    ULONG char_len = 0;
    LONG err = key_.QueryStringValue(name, NULL, &char_len);
    if (err == ERROR_SUCCESS) {
      value->resize(char_len - 1);
      err = key_.QueryStringValue(name, &(*value)[0], &char_len);
      if (err == ERROR_SUCCESS)
        return true;
    }
  }

  if (default_value != NULL) {
    *value = default_value;
    return true;
  }

  return false;
}

bool Preferences::ReadStringValue(const wchar_t* name,
                                  std::string* value,
                                  const char* default_value) {
  std::wstring temp_output;
  std::wstring temp_default;

  if (default_value != NULL)
    temp_default = base::UTF8ToWide(default_value);

  bool result = ReadStringValue(name, &temp_output,
      default_value == NULL ? NULL : temp_default.c_str());

  if (result)
    *value = base::WideToUTF8(temp_output);

  return result;
}

bool Preferences::EnsureReadableKey() {
  if (key_)
    return true;

  LONG err = key_.Open(HKEY_CURRENT_USER, config::kSettingsKey, KEY_READ);
  return err == ERROR_SUCCESS;
}

bool Preferences::EnsureWritableKey() {
  if (key_)
    return true;

  LONG err = key_.Create(HKEY_CURRENT_USER, config::kSettingsKey);
  return err == ERROR_SUCCESS;
}
