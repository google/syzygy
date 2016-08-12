// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/testing/metrics.h"

#include <limits>
#include "base/command_line.h"
#include "base/environment.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "base/win/scoped_handle.h"
#include "syzygy/version/syzygy_version.h"

namespace testing {

namespace {

// The metrics will be written to a log file with the following extension,
// directly alongside the executable that is emitting metrics. By convention
// all test executables are in the root of the configuration output directory.
static const wchar_t kMetricsFileName[] = L"metrics.csv";

// The maximum allowable size of the metrics file. This prevents local
// developers metric files from growing monotonically and getting out of
// control. This needs to be amply large for the set of metrics that will be
// emitted in a single run of unittests.
static const size_t kMetricsFileMaxSize = 1 * 1024 * 1024;

// The environment variable where the metrics are configured.
static const char kMetricsEnvVar[] = "SYZYGY_UNITTEST_METRICS";

// Switches for controlling metrics.
static const char kEmitToLog[] = "emit-to-log";
static const char kEmitToWaterfall[] = "emit-to-waterfall";

// The current build configuration.
static const char kBuildConfig[] =
#ifdef _COVERAGE_BUILD
    "Coverage";
#else
#ifdef NDEBUG
#ifdef OFFICIAL_BUILD
    "Official";
#else
    "Release";
#endif  // OFFICIAL_BUILD
#else
    "Debug";
#endif  // NDEBUG
#endif  // _COVERAGE_BUILD

// A global lock used by metrics.
base::Lock metrics_lock;

// Global metrics configuration. This is initialized from the environment.
struct MetricsConfiguration {
  bool emit_to_log;
  bool emit_to_waterfall;
} metrics_config = { false, false };

// Parses metrics configuration from the environment.
void ParseMetricsConfiguration() {
  base::Environment* env = base::Environment::Create();
  DCHECK_NE(static_cast<base::Environment*>(nullptr), env);

  // If there's no environment variable then there's nothing to parse.
  std::string s;
  if (!env->GetVar(kMetricsEnvVar, &s))
    return;

  // Build a command line object that we can use for parsing. Prefix the
  // environment variable with a dummy executable name.
  std::wstring cmd_line(L"foo.exe ");
  cmd_line.append(base::UTF8ToWide(s));
  base::CommandLine cmd = base::CommandLine::FromString(cmd_line);
  metrics_config.emit_to_log = cmd.HasSwitch(kEmitToLog);
  metrics_config.emit_to_waterfall = cmd.HasSwitch(kEmitToWaterfall);
}

// Generates the path to the metrics log.
base::FilePath GetMetricsLogPath() {
  base::FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);
  return exe_dir.Append(kMetricsFileName);
}

// Opens a file for exclusive writing. This tries in a loop but can fail
// permanently. Returns an empty handle on failure.
bool OpenForExclusiveWrite(const base::FilePath& path,
                           base::win::ScopedHandle* handle) {
  DCHECK_NE(static_cast<base::win::ScopedHandle*>(nullptr), handle);
  DWORD wait = 1;  // In milliseconds.
  for (size_t retries = 0; retries <= 10; ++retries) {
    handle->Set(::CreateFile(
        path.value().c_str(),
        FILE_APPEND_DATA,
        0,  // Exclusive access.
        nullptr,  // No security attributes.
        OPEN_ALWAYS,  // Create existing file, or create a new one.
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (handle->IsValid())
      return true;
    ::Sleep(wait);
    wait++;
  }
  return false;
}

// Deletes the specified file if its size exceeds the given
// threshold. Returns true on success, false otherwise.
bool DeleteFileIfTooLarge(const base::FilePath& path, size_t max_size) {
  // Get the file size in a retry loop.
  int64_t file_size = 0;
  DWORD wait = 1;
  bool got_size = false;
  for (size_t retries = 0; retries <= 10; ++retries) {
    if (!base::PathExists(path))
      return true;
    if (base::GetFileSize(path, &file_size)) {
      got_size = true;
      break;
    }
    ::Sleep(wait);
    wait++;
  }

  if (!got_size) {
    LOG(ERROR) << "Unable to determine metric file size: " << path.value();
    return false;
  }

  // If the file doesn't need to be deleted then return.
  if (file_size <= static_cast<int64_t>(max_size))
    return true;

  // Try to delete the file in a retry loop.
  wait = 1;
  for (size_t retries = 0; retries <= 10; ++retries) {
    if (base::DeleteFile(path, false)) {
      LOG(INFO) << "Delete large metric file: " << path.value();
      return true;
    }
    ::Sleep(wait);
    wait++;
  }

  LOG(ERROR) << "Unable to delete large metric file: " << path.value();
  return false;
}

// Emits a single line of data to the log file. Logs an error if this fails,
// succeeds silently.
void EmitLineToMetricsFile(const base::StringPiece& line) {
  base::FilePath path = GetMetricsLogPath();
  if (!DeleteFileIfTooLarge(path, kMetricsFileMaxSize))
    return;

  base::win::ScopedHandle handle;
  if (!OpenForExclusiveWrite(path, &handle)) {
    LOG(ERROR) << "Failed to acquire handle to metrics log.";
    return;
  }
  DCHECK(handle.IsValid());
  DWORD bytes_written = 0;
  if (!::WriteFile(handle.Get(),
                   line.data(),
                   static_cast<DWORD>(line.size()),
                   &bytes_written,
                   nullptr) ||
      bytes_written != line.size()) {
    LOG(ERROR) << "Failed to write line to metrics log.";
  }
}

struct ScopedInfoLogLevel {
  ScopedInfoLogLevel() : level(0) {
    level = logging::GetMinLogLevel();
    logging::SetMinLogLevel(logging::LOG_INFO);
  }
  ~ScopedInfoLogLevel() {
    logging::SetMinLogLevel(level);
  }
  int level;
};

// Emits a metric that will appear on the waterfall console.
void EmitMetricToWaterfall(const base::StringPiece& name,
                           const std::string& value) {
  ScopedInfoLogLevel scoped_info_log_level;
  LOG(INFO) << "Emitting metric to waterfall\n\n"
            << "@@@STEP_TEXT@" << name << " = " << value << "@@@\n";
}

// Emit a metric in a simple human readable format.
void EmitMetricToLogging(const base::StringPiece& name,
                         const std::string& value) {
  ScopedInfoLogLevel scoped_info_log_level;
  LOG(INFO) << "PERF: " << name << "=" << value;
}

void EmitMetric(const base::StringPiece& name, const std::string& value) {
  base::AutoLock auto_lock(metrics_lock);

  // Ensure the metric configuration is parsed from the environment.
  ParseMetricsConfiguration();

  // Build the CSV record.
  base::Time time = base::Time::Now();
  const version::SyzygyVersion& version = version::kSyzygyVersion;
  std::string record = base::StringPrintf(
      "%lld, "         // Time (in microseconds since epoch)
      "%d.%d.%d.%d, "  // Version
      "%s, "           // GitHash
      "%s, "           // Config
      "%s, "           // MetricName
      "%s\n",          // MetricValue
      time.ToInternalValue(),
      version.major(), version.minor(), version.build(), version.patch(),
      version.last_change().c_str(),
      kBuildConfig,
      name.data(),
      value.data());

  // Emit the record to the log.
  if (metrics_config.emit_to_log)
    EmitLineToMetricsFile(record);

  // And also emit it to the log or waterfall.
  if (metrics_config.emit_to_waterfall) {
    EmitMetricToWaterfall(name, value);
  } else {
    EmitMetricToLogging(name, value);
  }
}

}  // namespace

void EmitMetric(const base::StringPiece& name, int64_t value) {
  std::string s = base::StringPrintf("%lld", value);
  EmitMetric(name, s);
}

void EmitMetric(const base::StringPiece& name, uint64_t value) {
  std::string s = base::StringPrintf("%llu", value);
  EmitMetric(name, s);
}

void EmitMetric(const base::StringPiece& name, double value) {
  // Convert the metric value to a string.
  std::string s = base::StringPrintf(
      "%.*e", std::numeric_limits<double>::digits10, value);
  EmitMetric(name, s);
}

}  // namespace testing
