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
#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/event_trace_consumer_win.h"
#include "base/logging.h"
#include "sawbuck/viewer/kernel_log_consumer.h"
#include "sawbuck/viewer/log_consumer.h"


// The log consumer class we use to parse the logs on our behalf.
// There can only be one instance of this class in existence at a time.
class DumpLogConsumer
    : public EtwTraceConsumerBase<DumpLogConsumer>,
      public KernelLogParser,
      public LogParser {
 public:
  DumpLogConsumer();
  ~DumpLogConsumer();

  static void ProcessEvent(EVENT_TRACE* event);

 private:
  virtual void ProcessOneEvent(EVENT_TRACE* event);

  // Our current instance pointer, used to route the
  // log events to our sole instance.
  static DumpLogConsumer* current_;
};

DumpLogConsumer* DumpLogConsumer::current_ = NULL;

DumpLogConsumer::DumpLogConsumer() {
  DCHECK(current_ == NULL);
  current_ = this;
}

DumpLogConsumer::~DumpLogConsumer() {
  DCHECK(current_ == this);
  current_ = NULL;
}

void DumpLogConsumer::ProcessEvent(EVENT_TRACE* event) {
  DCHECK(current_);
  if (current_ != NULL)
    current_->ProcessOneEvent(event);
}

void DumpLogConsumer::ProcessOneEvent(EVENT_TRACE* event) {
  if (!KernelLogParser::ProcessOneEvent(event) ||
      !LogParser::ProcessOneEvent(event)) {
    LOG(INFO) << "Unhandled event";
  }
}

class LogDumpHandler
    : public KernelModuleEvents,
      public KernelPageFaultEvents,
      public KernelProcessEvents,
      public LogEvents {
 protected:
  // KernelModuleEvents implementation.
  virtual void OnModuleIsLoaded(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info);
  virtual void OnModuleUnload(DWORD process_id,
                              const base::Time& time,
                              const ModuleInformation& module_info);
  virtual void OnModuleLoad(DWORD process_id,
                            const base::Time& time,
                            const ModuleInformation& module_info);

  // KernelPageFaultEvents implementation.
  virtual void OnTransitionFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter);
  virtual void OnDemandZeroFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter);
  virtual void OnCopyOnWrite(DWORD process_id,
                             DWORD thread_id,
                             const base::Time& time,
                             sym_util::Address address,
                             sym_util::Address program_counter);
  virtual void OnGlobalPageFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter);
  virtual void OnHard(DWORD process_id,
                      DWORD thread_id,
                      const base::Time& time,
                      sym_util::Address address,
                      sym_util::Address program_counter);
  virtual void OnHardPageFault(DWORD process_id,
                               DWORD thread_id,
                               const base::Time& time,
                               const base::Time& initial_time,
                               sym_util::Offset offset,
                               sym_util::Address address,
                               sym_util::Address file_object,
                               DWORD thread_id2,
                               sym_util::ByteCount byte_count);

  // KernelProcessEvents implementation.
  virtual void OnProcessIsRunning(const base::Time& time,
                                  const ProcessInfo& process_info);
  virtual void OnProcessStarted(const base::Time& time,
                                const ProcessInfo& process_info);
  virtual void OnProcessEnded(const base::Time& time,
                              const ProcessInfo& process_info,
                              ULONG exit_status);

  // LogEvents implementation.
  virtual void OnLogMessage(UCHAR level,
                            DWORD process_id,
                            DWORD thread_id,
                            LARGE_INTEGER time_stamp,
                            size_t num_traces,
                            void** stack_trace,
                            size_t length,
                            const char* message);
};

void LogDumpHandler::OnModuleIsLoaded(DWORD process_id,
                                      const base::Time& time,
                                      const ModuleInformation& module_info) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnModuleUnload(DWORD process_id,
                                    const base::Time& time,
                                    const ModuleInformation& module_info) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnModuleLoad(DWORD process_id,
                                  const base::Time& time,
                                  const ModuleInformation& module_info) {
  // TODO(siggi): implement me.
}


// KernelPageFaultEvents implementation.
void LogDumpHandler::OnTransitionFault(DWORD process_id,
                                       DWORD thread_id,
                                       const base::Time& time,
                                       sym_util::Address address,
                                       sym_util::Address program_counter) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnDemandZeroFault(DWORD process_id,
                                       DWORD thread_id,
                                       const base::Time& time,
                                       sym_util::Address address,
                                       sym_util::Address program_counter) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnCopyOnWrite(DWORD process_id,
                                   DWORD thread_id,
                                   const base::Time& time,
                                   sym_util::Address address,
                                   sym_util::Address program_counter) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnGlobalPageFault(DWORD process_id,
                                       DWORD thread_id,
                                       const base::Time& time,
                                       sym_util::Address address,
                                       sym_util::Address program_counter) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnHard(DWORD process_id,
                            DWORD thread_id,
                            const base::Time& time,
                            sym_util::Address address,
                            sym_util::Address program_counter) {
  // TODO(siggi): implement me.
}

void LogDumpHandler::OnHardPageFault(DWORD process_id,
                                     DWORD thread_id,
                                     const base::Time& time,
                                     const base::Time& initial_time,
                                     sym_util::Offset offset,
                                     sym_util::Address address,
                                     sym_util::Address file_object,
                                     DWORD thread_id2,
                                     sym_util::ByteCount byte_count) {
  // TODO(siggi): implement me.
}

std::wostream& operator<< (std::wostream& str,
    const KernelProcessEvents::ProcessInfo& process) {
  str << L"{ \n"
      << L"  " << process.process_id << L",  // process_id\n"
      << L"  " << process.parent_id << L",  // parent_id\n"
      << L"  " << process.session_id << L",  // session_id\n";

  str << L"  {\n"
      << L"    " << process.user_sid.Revision << L",  // Revision\n"
      << L"    " << process.user_sid.SubAuthorityCount
      << L",  // SubAuthorityCount\n";

  str << L"    {";
  int num_values = arraysize(process.user_sid.IdentifierAuthority.Value);
  for (int i = 0; i < num_values; ++i) {
    str << (i == 0 ? L" " : L", ")
        << process.user_sid.IdentifierAuthority.Value[i];
  }
  str << L" },  // IdentifierAuthority\n";
  str << L"    {";
  for (int i = 0; i < process.user_sid.SubAuthorityCount; ++i) {
    str << (i == 0 ? L" " : L", ")
        << process.user_sid.SubAuthority[i];
  }
  str << L" },  // SubAuthority\n";
  str << L"  },  // user_sid\n";

  str << L"  \"" << UTF8ToWide(process.image_name) << L"\",  // image_name\n"
      << L"  L\"" << process.command_line << L"\",  // command_line\n"
      << L"},\n";

  return str;
}

// KernelProcessEvents implementation.
void LogDumpHandler::OnProcessIsRunning(const base::Time& time,
                                        const ProcessInfo& process_info) {
  std::wcout << L"Running:\n" << process_info;
}

void LogDumpHandler::OnProcessStarted(const base::Time& time,
                                      const ProcessInfo& process_info) {
  std::wcout << L"Started:\n" << process_info;
}

void LogDumpHandler::OnProcessEnded(const base::Time& time,
                                    const ProcessInfo& process_info,
                                    ULONG exit_status) {
  std::wcout << L"Ended:\n" << process_info;
}

// LogEvents implementation.
void LogDumpHandler::OnLogMessage(UCHAR level,
                          DWORD process_id,
                          DWORD thread_id,
                          LARGE_INTEGER time_stamp,
                          size_t num_traces,
                          void** stack_trace,
                          size_t length,
                          const char* message) {
  // TODO(siggi): implement me.
}

int Error(const std::wstring& error) {
  std::wcout << error << std::endl;

  return 1;
}

int wmain(int argc, const wchar_t** argv) {
  base::AtExitManager at_exit;
  CommandLine::Init(0, NULL);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  std::vector<std::wstring> args = cmd_line->GetLooseValues();
  DumpLogConsumer consumer;
  for (size_t i = 0; i < args.size(); ++i) {
    HRESULT hr = consumer.OpenFileSession(args[i].c_str());

    if (FAILED(hr))
      return Error(StringPrintf(L"Error 0x%08X, opening file \"%ls\"",
                                hr, args[i]));
  }

  LogDumpHandler handler;
  consumer.set_module_event_sink(&handler);
  consumer.set_page_fault_event_sink(&handler);
  consumer.set_process_event_sink(&handler);
  consumer.set_event_sink(&handler);

  HRESULT hr = consumer.Consume();
  if (FAILED(hr))
    return Error(StringPrintf(L"Error 0x%08X consuming log files", hr));

  return 0;
}
