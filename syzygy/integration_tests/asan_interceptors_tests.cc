// Copyright 2013 Google Inc. All Rights Reserved.
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
#include "syzygy/integration_tests/asan_interceptors_tests.h"

#include <windows.h>  // NOLINT

#include <algorithm>
#include <string>

namespace testing {

namespace {

// Allocates and fills 2 strings. This is used to test the string interceptors.
void Alloc2TestStrings(char** str1, char** str2) {
  const char* str_value = "abc12";
  *str1 = new char[::strlen(str_value) + 1];
  ::strcpy(*str1, str_value);

  const char* keys_value = "12";
  *str2 = new char[::strlen(keys_value) + 1];
  ::strcpy(*str2, keys_value);
}

// Create a temporary filename.
bool CreateTemporaryFilename(std::wstring* filename) {
  if (filename == NULL)
    return false;

  wchar_t temp_path[MAX_PATH + 1] = {};
  wchar_t temp_filename[MAX_PATH + 1] = {};
  DWORD path_len = ::GetTempPath(MAX_PATH, temp_path);

  if (path_len >= MAX_PATH || path_len <= 0)
    return false;

  if (::GetTempFileName(temp_path, L"", 0, temp_filename) == 0)
    return false;

  *filename = temp_filename;

  return true;
}

// Initialize a temporary file with a given string and returns an handle to it.
HANDLE InitTemporaryFile(const std::wstring& filename,
                         const char* test_string) {
  std::string filename_utf8(filename.begin(), filename.end());

  // Creates a temporary file and write a string into it.
  FILE* temp_file_ptr = ::fopen(filename_utf8.c_str(), "w");
  if (temp_file_ptr == NULL)
    return 0;

  ::fwrite(test_string, sizeof(char), ::strlen(test_string), temp_file_ptr);

  ::fclose(temp_file_ptr);

  // Get a handle to the newly created file.
  HANDLE file_handle =
      ::CreateFile(filename.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  return file_handle;
}

}  // namespace

size_t AsanStrcspnKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = ::strlen(keys);
  keys[keys_len] = 'a';

  size_t result = ::strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = ::strcspn(str, keys - 1);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  size_t result = ::strcspn(str, keys);
  delete[] str;
  return result;
}

size_t AsanStrcspnSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = ::strlen(str);
  str[str_len] = 'a';

  size_t result = ::strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = ::strcspn(str - 1, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  size_t result = ::strcspn(str, keys);
  delete[] keys;
  return result;
}

size_t AsanStrlenOverflow() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  size_t str_len = ::strlen(str);
  str[str_len] = 'a';

  size_t result = ::strlen(str);
  delete[] str;
  return result;
}

size_t AsanStrlenUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  size_t result = ::strlen(str - 1);
  delete[] str;
  return result;
}

size_t AsanStrlenUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  delete[] str;
  size_t result = ::strlen(str);
  return result;
}

size_t AsanStrrchrOverflow() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  size_t str_len = ::strlen(str);
  str[str_len] = 'a';

  char* result = ::strrchr(str, 'c');
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrrchrUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  char* result = ::strrchr(str - 1, 'c');
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrrchrUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[::strlen(str_value) + 1];
  ::strcpy(str, str_value);

  delete[] str;
  char* result = ::strrchr(str, 'c');
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrcmpSrc1Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = ::strlen(str1);
  str1[str1_len] = 'a';

  size_t result = ::strcmp(str1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc1Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t result = ::strcmp(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc1UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str1;
  size_t result = ::strcmp(str1, str2);
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = ::strlen(str1);
  str1[str1_len] = 'a';

  size_t result = ::strcmp(str1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t result = ::strcmp(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str2;
  size_t result = ::strcmp(str1, str2);
  delete[] str1;
  return result;
}

size_t AsanStrpbrkKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = ::strlen(keys);
  keys[keys_len] = 'a';

  char* result = ::strpbrk(str, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  char* result = ::strpbrk(str, keys - 1);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  char* result = ::strpbrk(str, keys);
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = ::strlen(str);
  str[str_len] = 'a';

  char* result = ::strpbrk(str, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  char* result = ::strpbrk(str - 1, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  char* result = ::strpbrk(str, keys);
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = ::strlen(str1);
  str1[str1_len] = 'a';

  char* result = ::strstr(str1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  char* result = ::strstr(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str1;
  char* result = ::strstr(str1, str2);
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = ::strlen(str1);
  str1[str1_len] = 'a';

  char* result = ::strstr(str1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  char* result = ::strstr(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str2;
  char* result = ::strstr(str1, str2);
  delete[] str1;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrspnKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = ::strlen(keys);
  keys[keys_len] = 'a';

  size_t result = ::strspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = ::strspn(str, keys - 1);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  size_t result = ::strspn(str, keys);
  delete[] str;
  return result;
}

size_t AsanStrspnSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = ::strlen(str);
  str[str_len] = 'a';

  size_t result = ::strspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = ::strspn(str - 1, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  size_t result = ::strspn(str, keys);
  delete[] keys;
  return result;
}

size_t AsanStrncpySrcOverflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[::strlen(str_value) + 1];
  ::strcpy(src, str_value);

  char* destination = new char[::strlen(str_value) + 2];

  size_t source_len = ::strlen(src);
  src[source_len] = 'a';

  char* result = ::strncpy(destination, src, source_len + 2);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpySrcUnderflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[::strlen(str_value) + 1];
  ::strcpy(src, str_value);

  char* destination = new char[::strlen(str_value) + 1];

  char* result = ::strncpy(destination, src - 1, ::strlen(str_value) + 1);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpySrcUseAfterFree() {
  const char* str_value = "test_strncpy";
  char* src = new char[::strlen(str_value) + 1];
  ::strcpy(src, str_value);

  char* destination = new char[::strlen(str_value) + 1];

  delete[] src;
  char* result = ::strncpy(destination, src, ::strlen(str_value) + 1);

  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstOverflow() {
  const char* str_value = "test_strncpy";

  const char* long_str_value = "test_strncpy_long_source";
  char* long_source = new char[::strlen(long_str_value) + 1];
  ::strcpy(long_source, long_str_value);

  char* destination = new char[::strlen(str_value) + 1];
  std::string original_data;
  original_data.resize(::strlen(long_str_value));
  NonInterceptedReads(destination, ::strlen(long_str_value), &original_data[0]);
  char* result = ::strncpy(destination, long_source, ::strlen(long_str_value));
  NonInterceptedWrites(&original_data[0], ::strlen(long_str_value),
      destination);

  delete[] long_source;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstUnderflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[::strlen(str_value) + 1];
  ::strcpy(src, str_value);

  char* destination = new char[::strlen(str_value) + 1];

  char last_header_val = NonInterceptedRead(destination - 1);
  char* result = ::strncpy(destination - 1, src, ::strlen(str_value) + 1);
  NonInterceptedWrite(destination - 1, last_header_val);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstUseAfterFree() {
  const char* str_value = "test_strncpy";
  char* src = new char[::strlen(str_value) + 1];
  ::strcpy(src, str_value);

  char* destination = new char[::strlen(str_value) + 1];

  delete[] destination;
  char* result = ::strncpy(destination, src, ::strlen(str_value) + 1);

  delete[] src;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixOverflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";
  size_t suffix_len = ::strlen(suffix_value);

  char* mem = new char[::strlen(prefix_value) + suffix_len + 2];
  ::strcpy(mem, prefix_value);

  char* suffix = new char[suffix_len + 1];
  ::strcpy(suffix, suffix_value);

  char first_trailer_val = NonInterceptedRead(&suffix[suffix_len + 1]);
  suffix[suffix_len] = 'a';
  NonInterceptedWrite(&suffix[suffix_len + 1], static_cast<char>(0));
  char* result = ::strncat(mem, suffix, suffix_len + 2);
  NonInterceptedWrite(&suffix[suffix_len + 1], first_trailer_val);
  suffix[suffix_len] = 0;

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixUnderflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[::strlen(prefix_value) + ::strlen(suffix_value) + 1];
  ::strcpy(mem, prefix_value);

  char* suffix = new char[::strlen(suffix_value) + 1];
  ::strcpy(suffix, suffix_value);

  char* result = ::strncat(mem, suffix - 1, ::strlen(suffix));

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixUseAfterFree() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[::strlen(prefix_value) + ::strlen(suffix_value) + 1];
  ::strcpy(mem, prefix_value);

  char* suffix = new char[::strlen(suffix_value) + 1];
  ::strcpy(suffix, suffix_value);

  delete[] suffix;
  char* result = ::strncat(mem, suffix, ::strlen(suffix_value));

  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstOverflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  size_t mem_size = ::strlen(prefix_value) + ::strlen(suffix_value);
  // Create an array that won't have enough room for the terminating null
  // character.
  char* mem = new char[mem_size];
  ::strcpy(mem, prefix_value);

  std::string original_data;
  char first_trailer_val = NonInterceptedRead(&mem[mem_size]);
  char* result = ::strncat(mem, suffix_value, ::strlen(suffix_value) + 1);
  NonInterceptedWrite(&mem[mem_size], first_trailer_val);

  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstUnderflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[::strlen(prefix_value) + ::strlen(suffix_value) + 1];
  ::strcpy(mem, prefix_value);

  char* suffix = new char[::strlen(suffix_value) + 1];
  ::strcpy(suffix, suffix_value);

  char last_header_val = NonInterceptedRead(mem - 1);
  char* result = ::strncat(mem - 1, suffix, ::strlen(suffix));
  NonInterceptedWrite(mem - 1, last_header_val);

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstUseAfterFree() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[::strlen(prefix_value) + ::strlen(suffix_value) + 1];
  ::strcpy(mem, prefix_value);

  char* suffix = new char[::strlen(suffix_value) + 1];
  ::strcpy(suffix, suffix_value);

  delete[] mem;
  char* result = ::strncat(mem, suffix, ::strlen(suffix));

  delete[] suffix;
  return reinterpret_cast<size_t>(result);
}

size_t AsanReadFileOverflow() {
  std::wstring temp_filename;

  if (!CreateTemporaryFilename(&temp_filename))
    return false;

  const char* kTestString = "Test of asan_ReadFile: Overflow";
  const size_t kTestStringLength = ::strlen(kTestString);

  HANDLE file_handle = InitTemporaryFile(temp_filename, kTestString);

  if (file_handle == INVALID_HANDLE_VALUE)
    return 0;

  char* alloc = new char[kTestStringLength];
  memset(alloc, 0, kTestStringLength);

  // Do an overflow on the destination buffer. It should be detected by the
  // ASan interceptor of ReadFile.
  DWORD bytes_read = 0;
  if (!::ReadFile(file_handle,
                  alloc,
                  kTestStringLength + 1,
                  &bytes_read,
                  NULL)) {
    return 0;
  }

  delete[] alloc;

  if (!::CloseHandle(file_handle))
    return 0;

  if (!::DeleteFile(temp_filename.c_str()))
    return 0;

  return bytes_read;
}

size_t AsanReadFileUseAfterFree() {
  std::wstring temp_filename;

  if (!CreateTemporaryFilename(&temp_filename))
    return false;

  const char* kTestString = "Test of asan_ReadFile: use-after-free";
  const size_t kTestStringLength = ::strlen(kTestString) + 1;

  HANDLE file_handle = InitTemporaryFile(temp_filename, kTestString);

  if (file_handle == INVALID_HANDLE_VALUE)
    return 0;

  char* alloc = new char[kTestStringLength];
  memset(alloc, 0, kTestStringLength);

  delete[] alloc;

  DWORD bytes_read = 0;

  // Do an use-after-free on the destination buffer. It should be detected by
  // the ASan interceptor of ReadFile.
  if (!::ReadFile(file_handle,
                  alloc,
                  kTestStringLength,
                  &bytes_read,
                  NULL)) {
    return 0;
  }

  if (!::CloseHandle(file_handle))
    return 0;

  if (!::DeleteFile(temp_filename.c_str()))
    return 0;

  return bytes_read;
}

size_t AsanWriteFileOverflow() {
  std::wstring temp_filename;

  if (!CreateTemporaryFilename(&temp_filename))
    return false;

  const char* kTestString = "Test of asan_WriteFile: overflow";
  const size_t kTestStringLength = ::strlen(kTestString) + 1;

  HANDLE file_handle = InitTemporaryFile(temp_filename, "");

  if (file_handle == INVALID_HANDLE_VALUE)
    return 0;

  char* alloc = new char[kTestStringLength];
  ::strcpy(alloc, kTestString);

  // Do an overflow on the input buffer. It should be detected by the ASan
  // interceptor of WriteFile.
  DWORD bytes_written = 0;
  if (!::WriteFile(file_handle,
                   alloc,
                   kTestStringLength + 1,
                   &bytes_written,
                   NULL)) {
    return 0;
  }

  delete[] alloc;

  if (!::CloseHandle(file_handle))
    return 0;

  if (!::DeleteFile(temp_filename.c_str()))
    return 0;

  return bytes_written;
}

size_t AsanWriteFileUseAfterFree() {
  std::wstring temp_filename;

  if (!CreateTemporaryFilename(&temp_filename))
    return false;

  const char* kTestString = "Test of asan_WriteFile: use-after-free";
  const size_t kTestStringLength = ::strlen(kTestString) + 1;

  HANDLE file_handle = InitTemporaryFile(temp_filename, "");

  if (file_handle == INVALID_HANDLE_VALUE)
    return 0;

  char* alloc = new char[kTestStringLength];
  ::strcpy(alloc, kTestString);

  delete[] alloc;

  DWORD bytes_written = 0;

  // Do a use-after-free on the input buffer. It should be detected by the ASan
  // interceptor of WriteFile.
  if (!::WriteFile(file_handle,
                   alloc,
                   kTestStringLength,
                   &bytes_written,
                   NULL)) {
    return 0;
  }

  if (!::CloseHandle(file_handle))
    return 0;

  if (!::DeleteFile(temp_filename.c_str()))
    return 0;

  return bytes_written;
}

size_t AsanWcsrchrOverflow() {
  const wchar_t* wstr_value = L"abc1";
  wchar_t* wstr = new wchar_t[wcslen(wstr_value) + 1];
  wcscpy(wstr, wstr_value);

  size_t wstr_len = wcslen(wstr);
  wstr[wstr_len] = L'a';

  wchar_t* result = wcsrchr(wstr, L'c');
  delete[] wstr;
  return reinterpret_cast<size_t>(result);
}

size_t AsanWcsrchrUnderflow() {
  const wchar_t* wstr_value = L"abc1";
  wchar_t* wstr = new wchar_t[wcslen(wstr_value) + 1];
  wcscpy(wstr, wstr_value);

  wchar_t* result = wcsrchr(wstr - 1, L'c');
  delete[] wstr;
  return reinterpret_cast<size_t>(result);
}

size_t AsanWcsrchrUseAfterFree() {
  const wchar_t* wstr_value = L"abc1";
  wchar_t* wstr = new wchar_t[wcslen(wstr_value) + 1];
  wcscpy(wstr, wstr_value);

  delete[] wstr;
  wchar_t* result = wcsrchr(wstr, L'c');
  return reinterpret_cast<size_t>(result);
}

// TODO(chrisha|sebmarchand): These should be in a separate file, as they
// aren't really interceptor tests.

size_t AsanCorruptedBlock() {
  size_t* mem = new size_t[10];
  size_t original_value = NonInterceptedRead(&mem[-1]);
  NonInterceptedWrite(&mem[-1], original_value + 1);
  size_t ret = mem[0];
  delete[] mem;
  return ret;
}

size_t AsanCorruptedBlockInQuarantine() {
  size_t* mem = new size_t[10];
  size_t ret = mem[0];
  delete[] mem;

  // We modify the block after deletion so that it will cause an error to be
  // fired when the block is trimmed from the quarantine.
  size_t original_value = NonInterceptedRead(&mem[0]);
  NonInterceptedWrite(&mem[0], original_value + 1);

  return ret;
}

}  // namespace testing
