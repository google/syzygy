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
// Provider settings class implementation.
#include "sawbuck/viewer/provider_configuration.h"

#include <atlbase.h>
#include "base/logging.h"
#include "sawbuck/viewer/const_config.h"

ProviderConfiguration::ProviderConfiguration() {
}

void ProviderConfiguration::Copy(const ProviderConfiguration& other) {
  settings_ = other.settings_;
}

bool ProviderConfiguration::ReadProviders() {
  settings_.clear();

  CRegKey providers;
  LONG err = providers.Open(HKEY_LOCAL_MACHINE,
                            config::kProviderNamesKey,
                            KEY_READ);
  if (err != ERROR_SUCCESS) {
    LOG(ERROR) << "Failed to open provider names key";
    return false;
  }

  for (DWORD index = 0; true; ++index) {
    wchar_t tmp_string[256];
    DWORD tmp_len = arraysize(tmp_string);
    err = providers.EnumKey(index, tmp_string, &tmp_len);
    if (err == ERROR_NO_MORE_ITEMS) {
      break;
    } else if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error enumerating provider names" << err;
      continue;
    }

    GUID provider_guid = {};
    if (FAILED(::CLSIDFromString(tmp_string, &provider_guid))) {
      LOG(ERROR) << "Non-GUID provider \"" << tmp_string << "\"";
      continue;
    }

    // Open the provider key, read its name etc.
    CRegKey provider;
    err = provider.Open(providers, tmp_string);
    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error opening provider key " << tmp_string << ", " << err;
      continue;
    }

    tmp_len = arraysize(tmp_string);
    err = provider.QueryStringValue(NULL, tmp_string, &tmp_len);
    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error reading provider name " << err;
      continue;
    }

    // Read the default trace level, defaulting to INFO on error.
    DWORD default_level = TRACE_LEVEL_INFORMATION;
    provider.QueryDWORDValue(config::kProviderDefaultLevelValue, default_level);

    // Read the default trace flags, defaulting to all-on.
    DWORD default_flags = 0xFFFFFFFF;
    provider.QueryDWORDValue(config::kProviderDefaultFlagsValue, default_flags);

    settings_.push_back(Settings());
    Settings& settings = settings_.back();
    settings.provider_guid = provider_guid;
    settings.provider_name = tmp_string;
    settings.log_level = static_cast<base::win::EtwEventLevel>(default_level);
    settings.enable_flags = default_flags;

    // Read the flags names and value.
    CRegKey flags;
    err = flags.Open(provider, config::kProviderFlagsKey);
    if (err != ERROR_SUCCESS)
      continue;

    for (int flags_index = 0; true; ++flags_index) {
      tmp_len = arraysize(tmp_string);
      err = flags.EnumKey(flags_index, tmp_string, &tmp_len);
      if (err == ERROR_NO_MORE_ITEMS) {
        break;
      } else if (err != ERROR_SUCCESS) {
        LOG(ERROR) << "Error enumerating provider names" << err;
        continue;
      }

      CRegKey flag;
      err = flag.Open(flags, tmp_string);
      if (err != ERROR_SUCCESS) {
        LOG(ERROR) << "Error reading opening flag "
            << tmp_string << ", " << err;
        continue;
      }

      DWORD mask = 0;
      err = flag.QueryDWORDValue(NULL, mask);
      settings.flag_names.push_back(std::make_pair(tmp_string, mask));
    }
  }

  return true;
}

bool ProviderConfiguration::ReadSettings() {
  CRegKey levels_key;
  LONG err = levels_key.Create(HKEY_CURRENT_USER,
                               config::kProviderLevelsKey,
                               0,
                               0,
                               KEY_WRITE);
  if (err == ERROR_FILE_NOT_FOUND) {
    // No settings initialized at all, the caller is pre-set to defaults.
    return true;
  } else if (err != ERROR_SUCCESS) {
    LOG(ERROR) << "Error reading provider log levels: " << err;

    return false;
  }

  for (size_t i = 0; i < settings_.size(); ++i) {
    wchar_t provider_name[40] = {};
    CHECK(::StringFromGUID2(settings_[i].provider_guid,
                            provider_name,
                            arraysize(provider_name)));

    CRegKey settings_key;
    err = settings_key.Open(levels_key, provider_name, KEY_READ);
    if (err == ERROR_FILE_NOT_FOUND) {
      // No settings key for this provider, keep moving.
      continue;
    } else if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error reading log level for provider " <<
          settings_[i].provider_name << ", error: " << err;
      continue;
    }

    DWORD log_level = 0;
    err = settings_key.QueryDWORDValue(config::kProviderLevelValue, log_level);
    if (err == ERROR_SUCCESS)
      settings_[i].log_level =
          static_cast<base::win::EtwEventLevel>(log_level);

    DWORD enable_flags = 0;
    err = settings_key.QueryDWORDValue(config::kProviderEnableFlagsValue,
                                       enable_flags);
    if (err == ERROR_SUCCESS)
      settings_[i].enable_flags = enable_flags;
  }

  return true;
}

bool ProviderConfiguration::WriteSettings() {
  CRegKey levels_key;
  LONG err = levels_key.Create(HKEY_CURRENT_USER,
                               config::kProviderLevelsKey,
                               0,
                               0,
                               KEY_WRITE);
  if (err != ERROR_SUCCESS) {
    LOG(ERROR) << "Error saving provider log levels: " << err;

    return false;
  }

  for (size_t i = 0; i < settings_.size(); ++i) {
    wchar_t provider_name[40] = {};
    CHECK(::StringFromGUID2(settings_[i].provider_guid,
                            provider_name,
                            arraysize(provider_name)));

    CRegKey settings_key;
    err = settings_key.Create(levels_key, provider_name);
    if (err == ERROR_SUCCESS) {
      err = settings_key.SetDWORDValue(config::kProviderLevelValue,
                                       settings_[i].log_level);
    }
    if (err == ERROR_SUCCESS) {
      err = settings_key.SetDWORDValue(config::kProviderEnableFlagsValue,
                                       settings_[i].enable_flags);
    }

    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error writing log level for provider " <<
          settings_[i].provider_name << ", error: " << err;
      return false;
    }
  }

  return true;
}
