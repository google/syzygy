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
// Provider settings class declaration.
#ifndef SAWBUCK_VIEWER_PROVIDER_CONFIGURATION_H_
#define SAWBUCK_VIEWER_PROVIDER_CONFIGURATION_H_

#include <vector>
#include "base/win/event_trace_provider.h"

class ProviderConfiguration {
 public:
  ProviderConfiguration();

  // Copies this from other.
  void Copy(const ProviderConfiguration& other);

  // Reads the provider information from root_key.
  bool ReadProviders();

  // Read and write provider settings from/to root_key.
  bool ReadSettings();
  bool WriteSettings();

  typedef std::vector<std::pair<std::wstring, base::win::EtwEventFlags>>
      FlagNameList;

  // Log level settings for a provider.
  struct Settings {
    // The provider's GUID.
    GUID provider_guid;
    // The provider's name.
    std::wstring provider_name;
    // The current log level.
    base::win::EtwEventLevel log_level;
    // The current enable flags.
    base::win::EtwEventFlags enable_flags;
    // A list of (name, mask) pairs, where mask may have
    // one or more bit set, and the associated name.
    FlagNameList flag_names;
  };

  // Accessor for the current settings.
  const std::vector<Settings>& settings() const { return settings_; }

 private:
  std::vector<Settings> settings_;

  DISALLOW_COPY_AND_ASSIGN(ProviderConfiguration);
};

#endif  // SAWBUCK_VIEWER_PROVIDER_CONFIGURATION_H_
