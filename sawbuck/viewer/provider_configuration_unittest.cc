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
// Provider settings unittests.
#include "sawbuck/viewer/provider_configuration.h"

#include <atlbase.h>
#include <statreg.h>
#include "gtest/gtest.h"
#include "sawbuck/viewer/registry_test.h"
#include "sawbuck/viewer/const_config.h"

namespace {

const wchar_t* kHKCUReplacement =
    L"Software\\Google\\InstallUtilUnittest\\HKCU";
const wchar_t* kHKLMReplacement =
    L"Software\\Google\\InstallUtilUnittest\\HKLM";

// This test fixture redirects the HKLM and HKCU registry hives for
// the duration of the test to make it independent of the machine
// and user settings.
class ProviderConfigurationTest : public testing::RegistryTest {
};

const wchar_t kProviderRegistrations[] = L""
L"HKLM {\r\n"
L"  NoRemove Software {\r\n"
L"    NoRemove Google {\r\n"
L"      ForceRemove Sawbuck {\r\n"
L"        Providers {\r\n"
L"          '{0562BFC3-2550-45b4-BD8E-A310583D3A6F}' = s 'Chrome Frame' {\r\n"
L"            val default_flags = d '&H00000001'\r\n"
L"            val default_level = d '2'\r\n"
L"            Flags {\r\n"
L"              Dummy = d '&H00000002'\r\n"
L"              StackDummyTrace = d '&H00000003'\r\n"
L"              StackTrace = d '&H00000001'\r\n"
L"            }\r\n"
L"          }\r\n"
L"          '{7FE69228-633E-4f06-80C1-527FEA23E3A7}' = s 'Chrome'\r\n"
L"        }\r\n"
L"      }\r\n"
L"    }\r\n"
L"  }\r\n"
L"}\r\n";

const GUID kChromeFrameGuid = {
    0x0562BFC3, 0x2550, 0x45b4,
    0xBD, 0x8E, 0xA3, 0x10, 0x58, 0x3D, 0x3A, 0x6F };

const GUID kChromeGuid = {
    0x7FE69228, 0x633E, 0x4f06,
    0x80, 0xC1, 0x52, 0x7F, 0xEA, 0x23, 0xE3, 0xA7 };

TEST_F(ProviderConfigurationTest, ReadProviders) {
  ASSERT_TRUE(Register(kProviderRegistrations));

  ProviderConfiguration settings;
  ASSERT_TRUE(settings.ReadProviders());

  ASSERT_EQ(2, settings.settings().size());
  const ProviderConfiguration::Settings* set = &settings.settings()[0];
  EXPECT_TRUE(kChromeFrameGuid == set->provider_guid);
  EXPECT_STREQ(L"Chrome Frame", set->provider_name.c_str());
  EXPECT_EQ(2, set->log_level);
  EXPECT_EQ(1, set->enable_flags);

  ASSERT_EQ(3, set->flag_names.size());
  EXPECT_STREQ(L"Dummy", set->flag_names[0].first.c_str());
  EXPECT_EQ(2, set->flag_names[0].second);
  EXPECT_STREQ(L"StackDummyTrace", set->flag_names[1].first.c_str());
  EXPECT_EQ(3, set->flag_names[1].second);
  EXPECT_STREQ(L"StackTrace", set->flag_names[2].first.c_str());
  EXPECT_EQ(1, set->flag_names[2].second);

  set = &settings.settings()[1];
  EXPECT_TRUE(kChromeGuid == set->provider_guid);
  EXPECT_STREQ(L"Chrome", set->provider_name.c_str());
  EXPECT_EQ(4, set->log_level);
  EXPECT_EQ(0xFFFFFFFF, set->enable_flags);
  ASSERT_EQ(0, set->flag_names.size());
}

const wchar_t kProviderConfiguration[] = L""
L"HKCU {\r\n"
L"  NoRemove Software {\r\n"
L"    NoRemove Google {\r\n"
L"      ForceRemove Sawbuck {\r\n"
L"        Levels {\r\n"
L"          '{0562BFC3-2550-45b4-BD8E-A310583D3A6F}' {\r\n"
L"            val enable_flags = d '&Hcafebabe'\r\n"
L"            val log_level = d '3'\r\n"
L"          }\r\n"
L"          '{7FE69228-633E-4f06-80C1-527FEA23E3A7}' {\r\n"
L"            val enable_flags = d '&H00000001'\r\n"
L"            val log_level = d '2'\r\n"
L"          }\r\n"
L"        }\r\n"
L"      }\r\n"
L"    }\r\n"
L"  }\r\n"
L"}\r\n";

TEST_F(ProviderConfigurationTest, ReadSettings) {
  ASSERT_TRUE(Register(kProviderRegistrations));
  ASSERT_TRUE(Register(kProviderConfiguration));

  ProviderConfiguration settings;
  ASSERT_TRUE(settings.ReadProviders());
  ASSERT_TRUE(settings.ReadSettings());

  ASSERT_EQ(2, settings.settings().size());
  const ProviderConfiguration::Settings* set = &settings.settings()[0];

  EXPECT_EQ(3, set->log_level);
  EXPECT_EQ(0xcafebabe, set->enable_flags);

  set = &settings.settings()[1];
  EXPECT_EQ(2, set->log_level);
  EXPECT_EQ(0x1, set->enable_flags);
}

TEST_F(ProviderConfigurationTest, WriteSettings) {
  ASSERT_TRUE(Register(kProviderRegistrations));

  ProviderConfiguration settings;
  ASSERT_TRUE(settings.ReadProviders());

  // Write the configuration from the default settings.
  ASSERT_TRUE(settings.WriteSettings());

  CRegKey key;
  ASSERT_EQ(ERROR_SUCCESS, key.Open(HKEY_CURRENT_USER,
                                    config::kProviderLevelsKey,
                                    KEY_READ));

  CRegKey provider;
  ASSERT_EQ(ERROR_SUCCESS, provider.Open(
      key, L"{0562BFC3-2550-45b4-BD8E-A310583D3A6F}", KEY_READ));

  DWORD temp = 0;
  ASSERT_EQ(ERROR_SUCCESS, provider.QueryDWORDValue(L"log_level", temp));
  EXPECT_EQ(2, temp);

  ASSERT_EQ(ERROR_SUCCESS, provider.QueryDWORDValue(L"enable_flags", temp));
  EXPECT_EQ(1, temp);

  ASSERT_EQ(ERROR_SUCCESS, provider.Open(
      key, L"{7FE69228-633E-4f06-80C1-527FEA23E3A7}", KEY_READ));

  ASSERT_EQ(ERROR_SUCCESS, provider.QueryDWORDValue(L"log_level", temp));
  EXPECT_EQ(4, temp);

  ASSERT_EQ(ERROR_SUCCESS, provider.QueryDWORDValue(L"enable_flags", temp));
  EXPECT_EQ(0xFFFFFFFF, temp);
}

}  // namespace
