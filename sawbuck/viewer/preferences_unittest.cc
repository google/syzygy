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
#include "sawbuck/viewer/preferences.h"
#include "gtest/gtest.h"
#include "sawbuck/viewer/registry_test.h"

namespace {

class PreferencesTest: public testing::RegistryTest {
};

const wchar_t kStringPrefences[] = L""
L"HKCU {\r\n"
L"  NoRemove Software {\r\n"
L"    NoRemove Google {\r\n"
L"      ForceRemove Sawbuck {\r\n"
L"        val foo = s 'bar'\r\n"
L"        val number = d '12345'\r\n"
L"      }\r\n"
L"    }\r\n"
L"  }\r\n"
L"}\r\n";

TEST_F(PreferencesTest, ReadStringValue) {
  Register(kStringPrefences);

  Preferences pref;

  // Wide string variants.
  {
    std::wstring str;
    EXPECT_TRUE(pref.ReadStringValue(L"foo", &str, L"default"));
    EXPECT_STREQ(L"bar", str.c_str());

    EXPECT_TRUE(pref.ReadStringValue(L"number", &str, L"default"));
    EXPECT_STREQ(L"default", str.c_str());

    EXPECT_FALSE(pref.ReadStringValue(L"number", &str, NULL));
  }

  {
    std::string str;
    EXPECT_TRUE(pref.ReadStringValue(L"foo", &str, "default"));
    EXPECT_STREQ("bar", str.c_str());

    EXPECT_TRUE(pref.ReadStringValue(L"number", &str, "default"));
    EXPECT_STREQ("default", str.c_str());

    EXPECT_FALSE(pref.ReadStringValue(L"number", &str, NULL));
  }
}

TEST_F(PreferencesTest, WriteStringValue) {
  Preferences pref;

  // Wide version.
  EXPECT_TRUE(pref.WriteStringValue(L"foo", L"bar"));

  std::wstring str;
  EXPECT_TRUE(pref.ReadStringValue(L"foo", &str, NULL));
  EXPECT_STREQ(L"bar", str.c_str());

  // UTF-8 version.
  EXPECT_TRUE(pref.WriteStringValue(L"foo", "bar2"));

  EXPECT_TRUE(pref.ReadStringValue(L"foo", &str, NULL));
  EXPECT_STREQ(L"bar2", str.c_str());
}

}  // namespace
