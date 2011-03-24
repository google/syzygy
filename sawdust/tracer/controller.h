// Copyright 2011 Google Inc.
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
// Controller of the tracing progress (turns tracing on and off).
#ifndef SAWDUST_TRACER_CONTROLLER_H_
#define SAWDUST_TRACER_CONTROLLER_H_

#include <windows.h>
#include <vector>

#include "base/file_path.h"
#include "base/synchronization/lock.h"
#include "base/time.h"
#include "base/win/event_trace_controller.h"

#include "sawdust/tracer/configuration.h"

// The controller (you really want one at a time) starts and stops logging
// sessions as defined by the configuration object passed to the Start method.
// This class is thread safe.
class TracerController {
 public:
  static const wchar_t kSawdustTraceSessionName[];
  static const int kMinimalLogAgeInSeconds = 180;

  TracerController() { }
  virtual ~TracerController() { }

  // Commences logging as defined in settings. It is a breach of contract to
  // call start while a session is ongoing. Successful call to Start will
  // create disk files as defined in config.
  HRESULT Start(const TracerConfiguration& config);

  // Stops the current logging session. If successful, paths of acquired logs
  // can be retrieved usign GetComplete* functions. These files are left on the
  // disk (the controller doesn't own them).
  HRESULT Stop();

  virtual bool IsRunning() const;
  bool IsLogWorthSaving() const;
  base::TimeDelta GetLoggingTimeSpan() const;

  // Query functions for retrieving completed log file names. Valid only once
  // logging session has been closed (by calling 'stop').
  bool GetCompletedEventLogFileName(FilePath* event_log) const;
  bool GetCompletedKernelEventLogFileName(FilePath* event_log) const;

 private:
  // A call to the Start method of the controller. Intended as a test seam only.
  virtual HRESULT StartLogging(base::win::EtwTraceController* controller,
                               base::win::EtwTraceProperties* properties,
                               const wchar_t* tracer_name);

  // Enables a |requested| providers with log_controller_. These that were
  // successfully enabled are added to |enabled|. Made virtual to serve as a
  // test seam.
  virtual void EnableProviders(
      const TracerConfiguration::ProviderDefinitions& requested,
      TracerConfiguration::ProviderDefinitions* enabled);

  // If a session identified by |session_name| is running, stop it. Returns
  // false if a session was running, but couldn't be stopped, true otherwise.
  // Made virtual to serve as a test seam.
  virtual bool VerifyAndStopIfRunning(const wchar_t* session_name) const;

  // Stop the kernel log and insert the path from where it can be picked up into
  // |log_path|. |log_path| was touched only when true is returned.
  virtual bool StopKernelLogging(FilePath* log_path);

  // Stop the app log and insert the path from where it can be picked up into
  // |log_path|. |current_providers| is in/out. It lists the providers to stop
  // and upon exit will contain only those providers that did not stop.
  // |log_path| is touched only when the call succeeded, while
  // |current_providers| might be always modified.
  // Separated and made virtual as a test seam.
  virtual HRESULT StopLogging(
      TracerConfiguration::ProviderDefinitions* current_providers,
      FilePath* log_path);

  static bool RetrieveCurrentLogFileName(
      const base::win::EtwTraceController& controller,
      const wchar_t* session_name,
      FilePath* file_path);

  // Controller for the logging session.
  base::win::EtwTraceController log_controller_;

  // Controller for the kernel logging session.
  base::win::EtwTraceController kernel_controller_;

  // The list of providers currently associated with log_controller.
  TracerConfiguration::ProviderDefinitions initialized_providers_;

  // Information about files that have already been 'acquired' and are ready
  // to ship (as opposed to 'pending').
  FilePath acquired_kernel_log_;
  FilePath acquired_chrome_log_;

  base::Time mru_start_point_;
  mutable base::Lock start_stop_lock_;

  DISALLOW_COPY_AND_ASSIGN(TracerController);
};

#endif  // SAWDUST_TRACER_CONTROLLER_H_
