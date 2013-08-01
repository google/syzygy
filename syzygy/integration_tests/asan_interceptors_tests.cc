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

#include <algorithm>

namespace testing {

namespace {

// Allocates and fills 2 strings. This is used to test the string interceptors.
void Alloc2TestStrings(char** str1, char** str2) {
  const char* str_value = "abc12";
  *str1 = new char[strlen(str_value) + 1];
  strcpy(*str1, str_value);

  const char* keys_value = "12";
  *str2 = new char[strlen(keys_value) + 1];
  strcpy(*str2, keys_value);
}

}  // namespace

size_t AsanStrcspnKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = strlen(keys);
  keys[keys_len] = 'a';

  size_t result = strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = strcspn(str, keys - 1);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  size_t result = strcspn(str, keys);
  delete[] str;
  return result;
}

size_t AsanStrcspnSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = strlen(str);
  str[str_len] = 'a';

  size_t result = strcspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = strcspn(str - 1, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrcspnSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  size_t result = strcspn(str, keys);
  delete[] keys;
  return result;
}

size_t AsanStrlenOverflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  size_t str_len = strlen(str);
  str[str_len] = 'a';

  size_t result = strlen(str);
  delete[] str;
  return result;
}

size_t AsanStrlenUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

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

  char* result = strrchr(str, 'c');
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrrchrUnderflow() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  char* result = strrchr(str - 1, 'c');
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrrchrUseAfterFree() {
  const char* str_value = "abc1";
  char* str = new char[strlen(str_value) + 1];
  strcpy(str, str_value);

  delete[] str;
  char* result = strrchr(str, 'c');
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrcmpSrc1Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = strlen(str1);
  str1[str1_len] = 'a';

  size_t result = strcmp(str1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc1Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t result = strcmp(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc1UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str1;
  size_t result = strcmp(str1, str2);
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = strlen(str1);
  str1[str1_len] = 'a';

  size_t result = strcmp(str1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t result = strcmp(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return result;
}

size_t AsanStrcmpSrc2UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str2;
  size_t result = strcmp(str1, str2);
  delete[] str1;
  return result;
}

size_t AsanStrpbrkKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = strlen(keys);
  keys[keys_len] = 'a';

  char* result = strpbrk(str, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  char* result = strpbrk(str, keys - 1);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  char* result = strpbrk(str, keys);
  delete[] str;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = strlen(str);
  str[str_len] = 'a';

  char* result = strpbrk(str, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  char* result = strpbrk(str - 1, keys);
  delete[] str;
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrpbrkSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  char* result = strpbrk(str, keys);
  delete[] keys;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = strlen(str1);
  str1[str1_len] = 'a';

  char* result = strstr(str1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  char* result = strstr(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc1UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str1;
  char* result = strstr(str1, str2);
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2Overflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  size_t str1_len = strlen(str1);
  str1[str1_len] = 'a';

  char* result = strstr(str1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2Underflow() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  char* result = strstr(str1 - 1, str2);
  delete[] str1;
  delete[] str2;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrstrSrc2UseAfterFree() {
  char* str1 = NULL;
  char* str2 = NULL;
  Alloc2TestStrings(&str1, &str2);

  delete[] str2;
  char* result = strstr(str1, str2);
  delete[] str1;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrspnKeysOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t keys_len = strlen(keys);
  keys[keys_len] = 'a';

  size_t result = strspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnKeysUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = strspn(str, keys - 1);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnKeysUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] keys;
  size_t result = strspn(str, keys);
  delete[] str;
  return result;
}

size_t AsanStrspnSrcOverflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t str_len = strlen(str);
  str[str_len] = 'a';

  size_t result = strspn(str, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnSrcUnderflow() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  size_t result = strspn(str - 1, keys);
  delete[] str;
  delete[] keys;
  return result;
}

size_t AsanStrspnSrcUseAfterFree() {
  char* str = NULL;
  char* keys = NULL;
  Alloc2TestStrings(&str, &keys);

  delete[] str;
  size_t result = strspn(str, keys);
  delete[] keys;
  return result;
}

size_t AsanStrncpySrcOverflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[strlen(str_value) + 1];
  strcpy(src, str_value);

  char* destination = new char[strlen(str_value) + 1];

  size_t source_len = strlen(src);
  src[source_len] = 'a';

  char* result = strncpy(destination, src, source_len + 1);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpySrcUnderflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[strlen(str_value) + 1];
  strcpy(src, str_value);

  char* destination = new char[strlen(str_value) + 1];

  char* result = strncpy(destination, src - 1, strlen(str_value) + 1);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpySrcUseAfterFree() {
  const char* str_value = "test_strncpy";
  char* src = new char[strlen(str_value) + 1];
  strcpy(src, str_value);

  char* destination = new char[strlen(str_value) + 1];

  delete[] src;
  char* result = strncpy(destination, src, strlen(str_value) + 1);

  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstOverflow() {
  const char* str_value = "test_strncpy";

  const char* long_str_value = "test_strncpy_long_source";
  char* long_source = new char[strlen(long_str_value) + 1];
  strcpy(long_source, long_str_value);

  char* destination = new char[strlen(str_value) + 1];

  char* result = strncpy(destination, long_source, strlen(long_str_value));

  delete[] long_source;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstUnderflow() {
  const char* str_value = "test_strncpy";
  char* src = new char[strlen(str_value) + 1];
  strcpy(src, str_value);

  char* destination = new char[strlen(str_value) + 1];

  char* result = strncpy(destination - 1, src, strlen(str_value) + 1);

  delete[] src;
  delete[] destination;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncpyDstUseAfterFree() {
  const char* str_value = "test_strncpy";
  char* src = new char[strlen(str_value) + 1];
  strcpy(src, str_value);

  char* destination = new char[strlen(str_value) + 1];

  delete[] destination;
  char* result = strncpy(destination, src, strlen(str_value) + 1);

  delete[] src;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixOverflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  size_t suffix_len = strlen(suffix);
  suffix[suffix_len] = 'a';

  char* result = strncpy(mem, suffix, suffix_len + 1);

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixUnderflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  char* result = strncpy(mem, suffix - 1, strlen(suffix));

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatSuffixUseAfterFree() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  delete[] suffix;
  char* result = strncpy(mem, suffix, strlen(suffix_value));

  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstOverflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  size_t prefix_len = strlen(prefix_value);
  mem[prefix_len] = 'a';

  char* result = strncat(mem, suffix, strlen(suffix));

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstUnderflow() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  char* result = strncat(mem - 1, suffix, strlen(suffix));

  delete[] suffix;
  delete[] mem;
  return reinterpret_cast<size_t>(result);
}

size_t AsanStrncatDstUseAfterFree() {
  const char* prefix_value = "test_";
  const char* suffix_value = "strncat";

  char* mem = new char[strlen(prefix_value) + strlen(suffix_value) + 1];
  strcpy(mem, prefix_value);

  char* suffix = new char[strlen(suffix_value) + 1];
  strcpy(suffix, suffix_value);

  delete[] mem;
  char* result = strncat(mem, suffix, strlen(suffix));

  delete[] suffix;
  return reinterpret_cast<size_t>(result);
}

}  // namespace testing
