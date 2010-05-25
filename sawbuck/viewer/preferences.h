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
// Utility class to make it easier to read and write configuration.
#ifndef SAWBUCK_VIEWER_PREFERENCES_H_
#define SAWBUCK_VIEWER_PREFERENCES_H_

#include <atlbase.h>
#include <string>

class Preferences {
 public:
  Preferences();

  bool WriteStringValue(const wchar_t* name, const std::wstring& value);
  bool WriteStringValue(const wchar_t* name, const std::string& value);

  bool ReadStringValue(const wchar_t* name,
                       std::string* value,
                       const char* default_value);
  bool ReadStringValue(const wchar_t* name,
                       std::wstring* value,
                       const wchar_t* default_value);
 private:
  bool EnsureReadableKey();
  bool EnsureWritableKey();

  CRegKey key_;
};

#endif  // SAWBUCK_VIEWER_PREFERENCES_H_
