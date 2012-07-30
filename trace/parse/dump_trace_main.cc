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

#include <windows.h>  // NOLINT
#include <stdio.h>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/threading/simple_thread.h"
#include "base/win/event_trace_consumer.h"
#include "base/win/event_trace_controller.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "syzygy/trace/parse/parser.h"
#include "syzygy/trace/service/service.h"

namespace {

using trace::parser::Parser;
using trace::parser::ParseEventHandler;
using trace::parser::ModuleInformation;

class TraceFileDumper : public ParseEventHandler {
 public:
  explicit TraceFileDumper(FILE* file)
      : file_(file ? file : stdout),
        indentation_("") {
  }

  void PrintFunctionEvent(const char* event_type,
                          base::Time time,
                          DWORD process_id,
                          DWORD thread_id,
                          const TraceEnterExitEventData* data) {
    DCHECK(event_type != NULL);
    DCHECK(data != NULL);
    DCHECK(data->function != NULL);
    ::fprintf(file_,
              "[%012lld] %s%s: process-id=%d; thread-id=%d; address=0x%08X\n",
              time.ToInternalValue(),
              indentation_,
              event_type,
              process_id,
              thread_id,
              data->function);
  }

  void PrintModuleEvent(const char* event_type,
                        base::Time time,
                        DWORD process_id,
                        DWORD thread_id,
                        const TraceModuleData* data) {
    DCHECK(event_type != NULL);
    DCHECK(data != NULL);
    DCHECK(data->module_base_addr != NULL);
    ::fprintf(file_,
              "[%012lld] %s: process-id=%d; thread-id=%d;"
              " module-name='%ls';"
              " module-addr=0x%08X; module-size=%d\n",
              time.ToInternalValue(),
              event_type,
              process_id,
              thread_id,
              data->module_name,
              data->module_base_addr,
              data->module_base_size);
  }

  void PrintOsVersionInfo(base::Time time,
                          const OSVERSIONINFOEX& os_version_info) {
    ::fprintf(file_,
              "[%012lld] %sOsVersionInfo: platform_id=%d; product_type=%d; "
                  "version=%d.%d; build=%d; service_pack=%d.%d\n",
              time.ToInternalValue(),
              indentation_,
              os_version_info.dwPlatformId,
              os_version_info.wProductType,
              os_version_info.dwMajorVersion,
              os_version_info.dwMinorVersion,
              os_version_info.dwBuildNumber,
              os_version_info.wServicePackMajor,
              os_version_info.wServicePackMinor);
  }

  void PrintSystemInfo(base::Time time, const SYSTEM_INFO& system_info) {
    ::fprintf(file_,
              "[%012lld] %sSystemInfo: cpu_arch=%d; cpu_count=%d; "
                  "cpu_level=%d; cpu_rev=%d\n",
              time.ToInternalValue(),
              indentation_,
              system_info.wProcessorArchitecture,
              system_info.dwNumberOfProcessors,
              system_info.wProcessorLevel,
              system_info.wProcessorRevision);
  }

  void PrintMemoryStatus(base::Time time, const MEMORYSTATUSEX& memory_status) {
    ::fprintf(file_,
              "[%012lld] %sMemoryStatus: load=%d; total_phys=%lld; "
                  "avail_phys=%lld\n",
              time.ToInternalValue(),
              indentation_,
              memory_status.dwMemoryLoad,
              memory_status.ullTotalPhys,
              memory_status.ullAvailPhys);
  }

  void PrintEnvironmentString(base::Time time,
                              const std::wstring& key,
                              const std::wstring& value) {
    ::fprintf(file_,
              "[%012lld] %sEnvironment: %ls=%ls\n",
              time.ToInternalValue(),
              indentation_,
              key.c_str(),
              value.c_str());
  }

  void PrintEnvironmentStrings(base::Time time,
                               const TraceEnvironmentStrings& env_strings) {
    for (size_t i = 0; i < env_strings.size(); ++i)
      PrintEnvironmentString(time, env_strings[i].first, env_strings[i].second);
  }

  virtual void OnProcessStarted(base::Time time,
                                DWORD process_id,
                                const TraceSystemInfo* data) {
    ::fprintf(file_,
              "[%012lld] OnProcessStarted: process-id=%d\n",
              time.ToInternalValue(),
              process_id);

    if (data == NULL)
      return;

    indentation_ = "    ";
    PrintOsVersionInfo(time, data->os_version_info);
    PrintSystemInfo(time, data->system_info);
    PrintMemoryStatus(time, data->memory_status);
    PrintEnvironmentStrings(time, data->environment_strings);
    indentation_ = "";
  }

  virtual void OnProcessEnded(base::Time time, DWORD process_id) {
    ::fprintf(file_,
              "[%012lld] OnProcessEnded: process-id=%d\n",
              time.ToInternalValue(),
              process_id);
  }

  virtual void OnFunctionEntry(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) {
    PrintFunctionEvent("OnFunctionEntry", time, process_id, thread_id, data);
  }

  virtual void OnFunctionExit(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceEnterExitEventData* data) {
    PrintFunctionEvent("OnFunctionEntry", time, process_id, thread_id, data);
  }

  virtual void OnBatchFunctionEntry(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceBatchEnterData* data) {
    DCHECK(data != NULL);
    DCHECK_EQ(thread_id, data->thread_id);
    ::fprintf(file_,
              "[%012lld] OnBatchFunctionEntry: " \
                  "process-id=%d; thread-id=%d; num-calls=%d\n",
              time.ToInternalValue(),
              process_id,
              thread_id,
              data->num_calls);

    // Explode the batch event into individual function entry events.
    TraceEnterExitEventData new_data = {};
    indentation_ = "    ";
    for (size_t i = 0; i < data->num_calls; ++i) {
      new_data.function = data->calls[i].function;
      OnFunctionEntry(base::Time::FromInternalValue(data->calls[i].tick_count),
                      process_id,
                      thread_id,
                      &new_data);
    }
    indentation_ = "";
  }

  virtual void OnProcessAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    PrintModuleEvent("OnProcessAttach", time, process_id, thread_id, data);
  }

  virtual void OnProcessDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) {
    PrintModuleEvent("OnProcessDetach", time, process_id, thread_id, data);
  }

  virtual void OnThreadAttach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    PrintModuleEvent("OnThreadAttach", time, process_id, thread_id, data);
  }

  virtual void OnThreadDetach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) {
    PrintModuleEvent("OnThreadDetach", time, process_id, thread_id, data);
  }

  virtual void OnInvocationBatch(base::Time time,
                                 DWORD process_id,
                                 DWORD thread_id,
                                 size_t num_invocations,
                                 const TraceBatchInvocationInfo* data) {
    DCHECK(data != NULL);
    ::fprintf(file_,
              "OnInvocationBatch: process-id=%d; thread-id=%d;\n",
              process_id,
              thread_id);
    for (size_t i = 0; i < num_invocations; ++i) {
      ::fprintf(file_,
                "    caller=0x%08X; function=0x%08X; num-calls=%d;\n"
                "    cycles-min=%lld; cycles-max=%lld; cycles-sum=%lld\n",
                data->invocations[i].caller,
                data->invocations[i].function,
                data->invocations[i].num_calls,
                data->invocations[i].cycles_min,
                data->invocations[i].cycles_max,
                data->invocations[i].cycles_sum);
    }
  }

  virtual void OnThreadName(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const base::StringPiece& thread_name) OVERRIDE {
    ::fprintf(file_, "OnThreadName: process-id=%d; thread-id=%d;\n"
              "    name=%s\n",
              process_id, thread_id, thread_name.as_string().c_str());
  }

  virtual void OnBasicBlockFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceBasicBlockFrequencyData* data) OVERRIDE {
    DCHECK(data != NULL);
    ::fprintf(file_,
              "OnBasicBlockFrequency: process-id=%d; thread-id=%d;\n"
              "    module-base-addr=0x%08X; module-base-size=%d\n"
              "    module-checksum=0x%08X; module-time-date-stamp=0x%08X\n"
              "    frequency-size=%d; basic-block-count=%d\n",
              data->module_base_addr,
              data->module_base_size,
              data->module_checksum,
              data->module_time_date_stamp,
              data->frequency_size,
              data->basic_block_count);
  }

 private:
  FILE* file_;
  const char* indentation_;

  DISALLOW_COPY_AND_ASSIGN(TraceFileDumper);
};

bool DumpTraceFiles(FILE* out_file, const std::vector<FilePath>& file_paths) {
  Parser parser;
  TraceFileDumper dumper(out_file);
  if (!parser.Init(&dumper))
    return false;

  std::vector<FilePath>::const_iterator iter = file_paths.begin();
  for (; iter != file_paths.end(); ++iter) {
    if (!parser.OpenTraceFile(*iter))
      return false;
  }

  return parser.Consume() && !parser.error_occurred();
}

}  // namespace

int main(int argc, const char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(
          L"",
          logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
          logging::DONT_LOCK_LOG_FILE,
          logging::APPEND_TO_OLD_LOG_FILE,
          logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  CHECK(cmd_line != NULL);

  std::vector<FilePath> trace_file_paths;
  for (size_t i = 0; i < cmd_line->GetArgs().size(); ++i)
    trace_file_paths.push_back(FilePath(cmd_line->GetArgs()[i]));

  if (trace_file_paths.empty()) {
    LOG(ERROR) << "No trace file paths specified.";

    ::fprintf(stderr,
              "Usage: %ls [--out=OUTPUT] TRACE_FILE(s)...\n\n",
              cmd_line->GetProgram().value().c_str());
    return 1;
  }

  FilePath out_file_path(cmd_line->GetSwitchValuePath("out"));
  file_util::ScopedFILE out_file;
  if (!out_file_path.empty()) {
    out_file.reset(file_util::OpenFile(out_file_path, "w"));
    if (out_file.get() == NULL) {
      LOG(ERROR) << "Failed to open output file: '" << out_file_path.value()
                 << "'.";
      return 1;
    }
  }

  if (!DumpTraceFiles(out_file.get(), trace_file_paths)) {
    LOG(ERROR) << "Failed to dump trace files.";
    return 1;
  }

  return 0;
}
