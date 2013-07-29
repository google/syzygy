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

namespace testing {

size_t AsanStrcspnKeysOverflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  const char* keys_value = "12";
  char* keys = new char[strlen(keys_value) + 1];
  strcpy(keys, keys_value);

  size_t keys_len = strlen(keys);
  keys[keys_len] = 'a';
  keys[keys_len + 1] = 0;

  size_t result = strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnKeysUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  const char* keys_value = "12";
  char* keys = new char[strlen(keys_value) + 1];
  strcpy(keys, keys_value);
  keys[-1] = 'a';

  size_t result = strcspn(str, keys - 1);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcOverflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  const char* keys_value = "12";
  char* keys = new char[strlen(keys_value) + 1];
  strcpy(keys, keys_value);

  size_t str_len = strlen(str);
  str[str_len] = 'a';
  str[str_len + 1] = 0;

  size_t result = strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);
  str[-1] = 'a';

  const char* keys_value = "12";
  char* keys = new char[strlen(keys_value) + 1];
  strcpy(keys, keys_value);

  size_t result = strcspn(str - 1, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  const char* keys_value = "12";
  char* keys = new char[strlen(keys_value) + 1];
  strcpy(keys, keys_value);

  delete[] str;
  delete[] keys;
  size_t result = strcspn(str - 1, keys);
  return result;
}

size_t AsanStrlenOverflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  size_t str_len = strlen(str);
  str[str_len] = 'a';
  str[str_len + 1] = 0;

  size_t result = strlen(str);
  delete[] str;
  return result;
}

size_t AsanStrlenUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);
  str[-1] = 'a';

  size_t result = strlen(str - 1);
  delete[] str;
  return result;
}

size_t AsanStrlenUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  delete[] str;
  size_t result = strlen(str);
  return result;
}

size_t AsanStrrchrOverflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  size_t str_len = strlen(str);
  str[str_len] = 'a';
  str[str_len + 1] = 0;

  size_t result = reinterpret_cast<size_t>(strrchr(str, 'c'));
  delete[] str;
  return result;
}

size_t AsanStrrchrUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);
  str[-1] = 'a';

  size_t result = reinterpret_cast<size_t>(strrchr(str - 1, 'c'));
  delete[] str;
  return result;
}

size_t AsanStrrchrUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  delete[] str;
  size_t result = reinterpret_cast<size_t>(strrchr(str, 'c'));
  return result;
}

}  // namespace testing
