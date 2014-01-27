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

#ifndef SYZYGY_COMMON_COM_UTILS_H_
#define SYZYGY_COMMON_COM_UTILS_H_

#include <windows.h>
#include <wtypes.h>
#include <ostream>

namespace common {

// Returns the provided hr if it is an error, otherwise default_error.
inline HRESULT AlwaysError(HRESULT hr, HRESULT default_error) {
  if (FAILED(hr)) {
    return hr;
  } else {
    return default_error;
  }
}

// Returns the provided hr if it is an error, otherwise E_FAIL.
inline HRESULT AlwaysError(HRESULT hr) {
  return AlwaysError(hr, E_FAIL);
}

// Converts a Win32 result code to a HRESULT. If the 'win32_code'
// does not indicate an error, it returns 'default_error'.
inline HRESULT AlwaysErrorFromWin32(DWORD win32_code,
                                    HRESULT default_error) {
  HRESULT hr = HRESULT_FROM_WIN32(win32_code);
  return AlwaysError(hr, default_error);
}

// Converts a Win32 result code to a HRESULT. If the 'win32_code'
// does not indicate an error, it returns E_FAIL
inline HRESULT AlwaysErrorFromWin32(DWORD win32_code) {
  return AlwaysErrorFromWin32(win32_code, E_FAIL);
}

// Returns the HRESULT equivalent of GetLastError(), unless it does not
// represent an error in which case it returns 'default_error'.
inline HRESULT AlwaysErrorFromLastError(HRESULT default_error) {
  return AlwaysErrorFromWin32(::GetLastError(), default_error);
}

// Returns the HRESULT equivalent of GetLastError(), unless it does not
// represent an error in which case it returns E_FAIL.
inline HRESULT AlwaysErrorFromLastError() {
  return AlwaysErrorFromLastError(E_FAIL);
}

// Return the specified string, or the empty string if it is NULL.
inline const wchar_t* ToString(BSTR str) {
  return str ? str : L"";
}

// Logs HRESULTs verbosely, with the error code and human-readable error
// text if available.
class LogHr {
 public:
  explicit LogHr(HRESULT hr) : hr_(hr) {}
 private:
  HRESULT hr_;
  friend std::ostream& operator<<(std::ostream&, const LogHr&);
};

std::ostream& operator<<(std::ostream& os, const LogHr& hr);

// Logs Windows errors verbosely, with the error code and human-readable error
// text if available.
class LogWe {
 public:
  LogWe() : we_(::GetLastError()) {}
  explicit LogWe(DWORD we) : we_(we) {}
 private:
  DWORD we_;
  friend std::ostream& operator<<(std::ostream&, const LogWe&);
};

std::ostream& operator<<(std::ostream& os, const LogWe& we);

}  // namespace common

#endif  // SYZYGY_COMMON_COM_UTILS_H_
