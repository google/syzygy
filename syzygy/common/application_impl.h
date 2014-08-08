// Copyright 2012 Google Inc. All Rights Reserved.
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
// Defines the template member function of the common::Application template
// class.
//
// This is not meant to be included directly.

#ifndef SYZYGY_COMMON_APPLICATION_IMPL_H_
#define SYZYGY_COMMON_APPLICATION_IMPL_H_

#include "base/win/scoped_com_initializer.h"
#include "syzygy/common/syzygy_version.h"

namespace common {

template <typename Impl, AppLoggingFlag kInitLogging>
Application<Impl, kInitLogging>::Application()
    : command_line_(CommandLine::ForCurrentProcess()) {
}

template <typename Impl, AppLoggingFlag kInitLogging>
int Application<Impl, kInitLogging>::Run() {
  // If we've been asked for our version, spit it out and quit.
  if (command_line_->HasSwitch("version")) {
    ::fprintf(out(), "%s\n", kSyzygyVersion.GetVersionString().c_str());
    return 0;
  }

  if (!InitializeLogging())
    return 1;

  if (!command_line_->HasSwitch("no-logo")) {
    LOG(INFO) << "Syzygy " << implementation_.name()
        << " Version " << kSyzygyVersion.GetVersionString() << ".";
    LOG(INFO) << "Copyright (c) Google Inc. All rights reserved.";
  }

  base::win::ScopedCOMInitializer com_initializer;
  if (!com_initializer.succeeded())
    return 1;

  if (!implementation_.ParseCommandLine(command_line_))
    return 1;

  if (!implementation_.SetUp())
    return 1;

  int result = implementation_.Run();

  implementation_.TearDown();

  return result;
}

template <typename Impl, AppLoggingFlag kInitLogging>
bool Application<Impl, kInitLogging>::InitializeLogging() {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  if ((kInitLogging == INIT_LOGGING_YES) &&
      !logging::InitLogging(settings)) {
    return false;
  }

  if (command_line_->HasSwitch("verbose")) {
    std::string value_str(command_line_->GetSwitchValueASCII("verbose"));
    base::TrimWhitespace(value_str, base::TRIM_ALL, &value_str);
    int value = 1;
    if (!base::StringToInt(value_str, &value))
      value = 1;
    logging::SetMinLogLevel(-::abs(value));
  }

  return true;
}

}  // namespace common

#endif  // SYZYGY_COMMON_APPLICATION_IMPL_H_
