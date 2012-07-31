// Copyright 2012 Google Inc.
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

#include "syzygy/common/syzygy_version.h"

namespace common {

namespace internal {

// A helper class to initialize and uninitialize COM within a context.
// TODO(rogerm): Move to com_utils library, either in sawbuck or create a
//     new one for syzygy.
class ScopedComInitializer {
 public:
  // Initialize COM in this context.
  ScopedComInitializer() : hresult_(::CoInitialize(NULL)) {
    if (!succeeded())
      LOG(ERROR) << "CoInitialize() failed: " << com::LogHr(hresult()) << ".";
  }

  // Deinitialized COM if initialization was successful.
  ~ScopedComInitializer() {
     if (succeeded())
       ::CoUninitialize();
   }

  // Get the status returned by the initialization.
  HRESULT hresult() const { return hresult_; }

  // True if the initialization succeeded.
  bool succeeded() const { return SUCCEEDED(hresult()); }

 private:
  // The status returned by the initialization.
  const HRESULT hresult_;
};

}  // namespace common::internal

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

  LOG(INFO) << "Syzygy " << implementation_.name()
            << " Version " << kSyzygyVersion.GetVersionString() << ".";
  LOG(INFO) << "Copyright (c) Google Inc. All rights reserved.";

  internal::ScopedComInitializer com_initializer;
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
  if ((kInitLogging == INIT_LOGGING_YES) &&
      !logging::InitLogging(
          L"",
          logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
          logging::DONT_LOCK_LOG_FILE,
          logging::APPEND_TO_OLD_LOG_FILE,
          logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return false;
  }

  if (command_line_->HasSwitch("verbose")) {
    std::string value_str(command_line_->GetSwitchValueASCII("verbose"));
    TrimWhitespace(value_str, TRIM_ALL, &value_str);
    int value = 1;
    if (!base::StringToInt(value_str, &value))
      value = 1;
    logging::SetMinLogLevel(-::abs(value));
  }

  return true;
}

}  // namespace common

#endif  // SYZYGY_COMMON_APPLICATION_IMPL_H_
