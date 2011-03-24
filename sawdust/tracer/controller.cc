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
// Controller for ETW events (a wrapper around base implementation).
#include "sawdust/tracer/controller.h"

#include "base/logging.h"
#include "sawdust/tracer/com_utils.h"

const wchar_t TracerController::kSawdustTraceSessionName[] =
    L"Sawdust logging session";

HRESULT TracerController::Start(const TracerConfiguration& config) {
  base::AutoLock lock(start_stop_lock_);
  DCHECK(log_controller_.session() == NULL);
  DCHECK(kernel_controller_.session() == NULL);
  DCHECK(initialized_providers_.empty());

  mru_start_point_ = base::Time();  // Set to null.
  acquired_kernel_log_.clear();  // Indicate there is no 'completed' log.
  acquired_chrome_log_.clear();

  if (!VerifyAndStopIfRunning(KERNEL_LOGGER_NAME) ||
      !VerifyAndStopIfRunning(kSawdustTraceSessionName)) {
      LOG(ERROR) << "Failed to reset the logging session.";
      return E_FAIL;
  }

  FilePath log_path, kernel_path;
  if (!config.GetLogFileName(&log_path) ||
      (config.IsKernelLoggingEnabled() &&
       !config.GetKernelLogFileName(&kernel_path))) {
    LOG(ERROR) << "Failed to get target file paths.";
    return E_FAIL;
  }

  HRESULT hr = S_OK;
  {
    base::win::EtwTraceProperties trace_definition;
    trace_definition.SetLoggerFileName(log_path.value().c_str());
    EVENT_TRACE_PROPERTIES* p = trace_definition.get();
    p->Wnode.ClientContext = 1;  // QPC timer accuracy.

    // Circular log, and get the entire space right away to avoid any trouble.
    p->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR |
                    EVENT_TRACE_FILE_MODE_PREALLOCATE;

    p->MaximumFileSize = config.GetLogFileSizeCapMb();
    p->FlushTimer = 30;  // 30 seconds flush lag.
    hr = StartLogging(&log_controller_, &trace_definition,
                      kSawdustTraceSessionName);
  }

  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to start a log session " <<
        kSawdustTraceSessionName << ", writing to " << log_path.value().c_str();
    return hr;
  }

  if (config.IsKernelLoggingEnabled()) {
    base::win::EtwTraceProperties trace_definition;
    trace_definition.SetLoggerFileName(kernel_path.value().c_str());
    EVENT_TRACE_PROPERTIES* p = trace_definition.get();
    p->Wnode.Guid = SystemTraceControlGuid;
    p->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR |
                     EVENT_TRACE_FILE_MODE_PREALLOCATE;
    p->MaximumFileSize = config.GetKernelLogFileSizeCapMb();
    // Get image load and process events.
    p->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_PROCESS;
    p->FlushTimer = 1;  // flush every second.
    p->BufferSize = 16;  // 16 K buffers.
    hr = StartLogging(&kernel_controller_, &trace_definition,
                      KERNEL_LOGGER_NAME);

    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to start a kernel log session, writing to " <<
          kernel_path.value().c_str();
      return hr;
    }
  }

  initialized_providers_.clear();
  EnableProviders(config.settings(), &initialized_providers_);
  mru_start_point_ = base::Time::Now();  // Keep the start point around.

  return initialized_providers_.empty() ? S_FALSE : hr;
}

HRESULT TracerController::Stop() {
  base::AutoLock lock(start_stop_lock_);

  StopKernelLogging(&acquired_kernel_log_);

  HRESULT hr = StopLogging(&initialized_providers_, &acquired_chrome_log_);

  if (FAILED(hr))
    return hr;

  return initialized_providers_.empty() ? S_OK : E_FAIL;
}

bool TracerController::IsRunning() const {
  base::AutoLock lock(start_stop_lock_);

  return (!initialized_providers_.empty() &&
          log_controller_.session() != NULL) ||
         (kernel_controller_.session() != NULL);
}

bool TracerController::GetCompletedEventLogFileName(FilePath* event_log) const {
  DCHECK(event_log != NULL);
  base::AutoLock lock(start_stop_lock_);
  if (acquired_chrome_log_.empty())
    return false;

  *event_log = acquired_chrome_log_;

  return true;
}

bool TracerController::GetCompletedKernelEventLogFileName(
    FilePath* event_log) const {
  DCHECK(event_log != NULL);
  base::AutoLock lock(start_stop_lock_);
  if (acquired_kernel_log_.empty())
    return false;

  *event_log = acquired_kernel_log_;

  return true;
}

bool TracerController::IsLogWorthSaving() const {
  return (IsRunning() &&
          GetLoggingTimeSpan().InSeconds() > kMinimalLogAgeInSeconds);
}

base::TimeDelta TracerController::GetLoggingTimeSpan() const {
  base::AutoLock lock(start_stop_lock_);

  if (mru_start_point_.is_null())
    return base::TimeDelta();
  else
    return base::Time::Now() - mru_start_point_;
}

HRESULT TracerController::StartLogging(
    base::win::EtwTraceController* controller,
    base::win::EtwTraceProperties* properties,
    const wchar_t* tracer_name) {
  DCHECK(controller != NULL);
  DCHECK(properties != NULL);
  DCHECK(tracer_name != NULL);
  return controller->Start(tracer_name, properties);
}

void TracerController::EnableProviders(
    const TracerConfiguration::ProviderDefinitions& requested,
    TracerConfiguration::ProviderDefinitions* enabled) {
  DCHECK(enabled != NULL);
  for (TracerConfiguration::ProviderDefinitions::const_iterator it =
       requested.begin(); it != requested.end(); ++it) {
    HRESULT hr_ins = log_controller_.EnableProvider(it->provider_guid,
                                                    it->log_level,
                                                    it->enable_flags);

    if (SUCCEEDED(hr_ins)) {
      enabled->push_back(*it);
    } else {
      LOG(WARNING) << "Failed to insert requested provider: "
        << it->provider_name << ". " << com::LogHr(hr_ins);
    }
  }
}

bool TracerController::VerifyAndStopIfRunning(
    const wchar_t* session_name) const {
  // Try and query the session properties.
  // This can only succeed if the session exists.
  base::win::EtwTraceProperties props;
  HRESULT hr = base::win::EtwTraceController::Query(session_name, &props);

  if (SUCCEEDED(hr)) {
    // Attempt to stop the running session. Since this is an abnormal condition,
    // we will log it.
    LOG(INFO) << "Sawdust had to stop a running session: " << session_name;
    hr = base::win::EtwTraceController::Stop(session_name, &props);

    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to stop trace session " <<
          session_name << com::LogHr(hr);
      return false;
    }
  }

  return true;
}

bool TracerController::StopKernelLogging(FilePath* log_path) {
  if (kernel_controller_.session() != NULL) {
    FilePath kernel_log_path;
    RetrieveCurrentLogFileName(kernel_controller_, KERNEL_LOGGER_NAME,
                               &kernel_log_path);

    HRESULT hr = kernel_controller_.Stop(NULL);

    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to stop kernel logging, " << com::LogHr(hr);
      return false;
    }

    *log_path = kernel_log_path;
    return true;
  }
  return false;
}

HRESULT TracerController::StopLogging(
    TracerConfiguration::ProviderDefinitions* current_providers,
    FilePath* log_path) {
  DCHECK(current_providers != NULL);
  DCHECK(log_controller_.session() != NULL);

  FilePath chrome_log_path;
  RetrieveCurrentLogFileName(log_controller_, kSawdustTraceSessionName,
                             &chrome_log_path);

  TracerConfiguration::ProviderDefinitions holdouts;
  for (TracerConfiguration::ProviderDefinitions::iterator it =
       current_providers->begin(); it != current_providers->end(); ++it) {
    HRESULT hr_k = log_controller_.DisableProvider(it->provider_guid);

    if (FAILED(hr_k)) {
      holdouts.push_back(*it);
      LOG(ERROR) << "Failed to disable a provider: " << it->provider_name <<
          ", " << com::LogHr(hr_k);
    }
  }
  // The purpose of the elaborate exercise with the 'holdouts' variable is to
  // retain these entries we failed to disable. This will let us know next
  // time around (when Start is called) to refuse to restart logging.
  *current_providers = holdouts;

  HRESULT hr = log_controller_.Stop(NULL);

  if (SUCCEEDED(hr))
    *log_path = chrome_log_path;

  return hr;
}

// Extract the log file name from the information about a running session
// contained in the |controller|.
bool TracerController::RetrieveCurrentLogFileName(
    const base::win::EtwTraceController& controller,
    const wchar_t* session_name,
    FilePath* file_path) {
  DCHECK(controller.session() != NULL) <<
      "Illegal call, object not associated with a valid session";
  if (controller.session() == NULL)
    return false;

  base::win::EtwTraceProperties properties;
  HRESULT hr = base::win::EtwTraceController::Query(session_name, &properties);

  if (FAILED(hr)) {
    LOG(ERROR) << "Trace controller " << session_name <<
        " failed. " << com::LogHr(hr);
    return false;
  }

  if (file_path != NULL)
    *file_path = FilePath(properties.GetLoggerFileName());

  return true;
}
