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
//
// Utilities for COM objects, error codes etc.

#include "syzygy/common/com_utils.h"

#include <atlbase.h>
#include <shlwapi.h>

#include "base/strings/string_util.h"

namespace common {

std::ostream& operator<<(std::ostream& os, const LogHr& hr) {
  // Looks up the human-readable system message for the HRESULT code
  // and since we're not passing any params to FormatMessage, we don't
  // want inserts expanded.
  const DWORD kFlags = FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS;
  char error_text[4096] = { '\0' };
  DWORD message_length = ::FormatMessageA(kFlags, 0, hr.hr_, 0, error_text,
                                          arraysize(error_text), NULL);
  std::string error(error_text);
  base::TrimWhitespaceASCII(error, base::TRIM_ALL, &error);

  return os << "[hr=0x" << std::hex << hr.hr_ << ", msg=" << error << "]";
}

std::ostream& operator<<(std::ostream& os, const LogWe& we) {
  // Looks up the human-readable system message for the Windows error code
  // and since we're not passing any params to FormatMessage, we don't
  // want inserts expanded.
  const DWORD kFlags = FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS;
  char error_text[4096] = { '\0' };
  DWORD message_length = ::FormatMessageA(kFlags, 0, we.we_, 0, error_text,
                                          arraysize(error_text), NULL);
  std::string error(error_text);
  base::TrimWhitespaceASCII(error, base::TRIM_ALL, &error);

  return os << "[we=" << we.we_ << ", msg=" << error << "]";
}

}  // namespace common
