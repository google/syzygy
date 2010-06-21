// Copyright 2010 Google Inc.
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
// A minimal viewer for call trace ETW logs.
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/event_trace_consumer_win.h"
#include "base/event_trace_controller_win.h"
#include "sawbuck/call_trace/call_trace_defs.h"
#include "sawbuck/call_trace/call_trace_parser.h"
#include "sawbuck/sym_util/module_cache.h"
#include "sawbuck/sym_util/symbol_cache.h"
#include "sawbuck/log_lib/buffer_parser.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"
#include <iostream>
#include <string>
#include <map>

using sym_util::Address;
using sym_util::ModuleCache;
using sym_util::SymbolCache;
using sym_util::Symbol;

std::ostream &operator<<(std::ostream& str, const Symbol& sym) {
  if (sym.file != L"")
    str << sym.file << "(" << sym.line << "): ";

  str << sym.mangled_name;
  if (sym.offset)
    str << " + 0x" << std::hex << sym.offset;

  return str;
}

class ViewerTraceConsumer
    : public EtwTraceConsumerBase<ViewerTraceConsumer>,
      public KernelModuleEvents,
      public CallTraceEvents {
 public:
  ViewerTraceConsumer(bool print_call_trace,
                      bool print_args,
                      bool print_retval,
                      DWORD process_id,
                      DWORD thread_id) :
      print_call_trace_(print_call_trace), print_args_(print_args),
      print_retval_(print_retval), process_id_(process_id),
      thread_id_(thread_id), last_time_(0), events_(0), buffers_(0) {
    consumer_ = this;
    kernel_log_parser_.set_module_event_sink(this);
    call_trace_parser_.set_call_trace_event_sink(this);
  }

  ~ViewerTraceConsumer() {
    consumer_ = NULL;
  }

  // KernelModuleEvents implementation.
  void OnModuleIsLoaded(DWORD process_id,
                        const base::Time& time,
                        const ModuleInformation& module_info) {
    module_cache_.ModuleLoaded(process_id, base::Time(), module_info);
  }

  void OnModuleUnload(DWORD process_id,
                      const base::Time& time,
                      const ModuleInformation& module_info) {
    module_cache_.ModuleUnloaded(process_id, time, module_info);
  }

  void OnModuleLoad(DWORD process_id,
                    const base::Time& time,
                    const ModuleInformation& module_info) {
    module_cache_.ModuleLoaded(process_id, time, module_info);
  }

  // CallTraceEvents implementation.
  void OnTraceEntry(base::Time time,
                    DWORD process_id,
                    DWORD thread_id,
                    const TraceEnterExitEventData* data) {
    OnTraceEntryExit(data, TRACE_ENTER_EVENT, time, process_id, thread_id);
  }

  void OnTraceExit(base::Time time,
                   DWORD process_id,
                   DWORD thread_id,
                   const TraceEnterExitEventData* data) {
    OnTraceEntryExit(data, TRACE_EXIT_EVENT, time, process_id, thread_id);
  }

  virtual void OnTraceBatchEnter(base::Time time,
                                 DWORD process_id,
                                 DWORD thread_id,
                                 const TraceBatchEnterData* data) {
    for (size_t i = 0; i < data->num_functions; ++i) {
      Symbol symbol;
      Address address =
          reinterpret_cast<Address>(data->functions[i]);
      std::wcout << process_id << L'\t'
          << thread_id << L'\t';
      if (Resolve(process_id, time, address, &symbol)) {
        std::wcout
            << address - symbol.module_base << L'(' << symbol.size << L")\t"
            << symbol.mangled_name;
      } else {
        std::wcout << data->functions[i] << L"(***UNKNOWN***)\t"
            << L"***UNKNOWN***";
      }
      std::wcout << std::endl;
    }
  }

  bool Resolve(DWORD process_id,
               base::Time time,
               Address address,
               Symbol* symbol) {
    ModuleLoadStateId id = module_cache_.GetStateId(process_id, time);
    SymbolCacheMap::iterator it(symbol_caches_.find(id));

    if (it == symbol_caches_.end()) {
      std::vector<ModuleInformation> modules;
      module_cache_.GetProcessModuleState(process_id, time, &modules);

      std::pair<SymbolCacheMap::iterator, bool> res =
          symbol_caches_.insert(std::make_pair(id, SymbolCache()));
      DCHECK_EQ(true, res.second);
      it = res.first;

      it->second.Initialize(modules.size(),
                            modules.empty() ? NULL : &modules[0]);
    }

    DCHECK(it != symbol_caches_.end());

    return it->second.GetSymbolForAddress(address, symbol);
  }

  void OnTraceEntryExit(const TraceEnterExitEventData* data,
                        TraceEventType type,
                        base::Time time,
                        DWORD process_id,
                        DWORD thread_id) {
    const char* msg = type == TRACE_ENTER_EVENT ? "> " : "< ";

    base::Time::Exploded exploded = {};
    time.LocalExplode(&exploded);

    char date_buf[256];
    sprintf_s(date_buf,
              "%02d:%02d:%02d:%03d",
              exploded.hour,
              exploded.minute,
              exploded.second,
              exploded.millisecond);

    std::cout << date_buf << '[' << process_id << '.'
              << thread_id << "]" << msg;

    for (size_t i = 0; i < data->depth; ++i) {
      std::cout << ' ';
    }

    Symbol symbol;
    if (Resolve(process_id,
                time,
                reinterpret_cast<Address>(data->function),
                &symbol)) {
      std::cout << symbol;
    } else {
      std::cout << data->function;
    }

    if (type == TRACE_ENTER_EVENT && print_args_) {
      std::cout << "(";
      for (size_t i = 0; i < ARRAYSIZE(data->args); ++i) {
        if (i > 0)
          std::cout << ", ";

        std::cout << "0x" << data->args[i];
      }
      std::cout << ")";
    }
    if (type == TRACE_EXIT_EVENT && print_retval_) {
      std::cout << " => " << "0x" << data->retval;
    }

    if (print_call_trace_) {
      for (size_t i = 0; i < data->num_traces; ++i) {
        std::cout << "\n\t";

        Symbol symbol;
        if (Resolve(process_id,
                    time,
                    reinterpret_cast<Address>(data->traces[i]),
                    &symbol)) {
          std::cout << '[' << symbol << ']';
        } else {
          std::cout << data->traces[i];
        }
      }
    }

    std::wcout << std::endl;
  }

  void OnEvent(PEVENT_TRACE event) {
    ++events_;

    DWORD process_id = event->Header.ProcessId;
    DWORD thread_id = event->Header.ThreadId;

    // Filter by given process/thread if appropriate.
    if ((process_id_ && process_id_ != process_id) ||
        (thread_id_ && thread_id_ != thread_id))
      return;

    if (!call_trace_parser_.ProcessOneEvent(event))
      kernel_log_parser_.ProcessOneEvent(event);
  }

  bool OnBuffer(PEVENT_TRACE_LOGFILE buffer) {
    ++buffers_;
    last_time_ = buffer->CurrentTime;
    return true;
  }

  static VOID WINAPI ProcessEvent(PEVENT_TRACE event) {
    consumer_->OnEvent(event);
  }

  static ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE buffer) {
    return consumer_->OnBuffer(buffer);
  }

  size_t events() const { return events_; }
  size_t buffers() const { return buffers_; }
  LONGLONG last_time() const { return last_time_; }

 private:
  bool print_call_trace_;
  bool print_args_;
  bool print_retval_;
  DWORD process_id_;
  DWORD thread_id_;

  typedef ModuleCache::ModuleLoadStateId ModuleLoadStateId;
  typedef std::map<ModuleLoadStateId, SymbolCache> SymbolCacheMap;
  SymbolCacheMap symbol_caches_;
  ModuleCache module_cache_;
  KernelLogParser kernel_log_parser_;
  CallTraceParser call_trace_parser_;

  LONGLONG last_time_;
  size_t events_;
  size_t buffers_;

  static ViewerTraceConsumer* consumer_;  // There shall be only one!
};

ViewerTraceConsumer* ViewerTraceConsumer::consumer_ = NULL;


int Usage(const wchar_t* prog) {
  std::wcout << L"Usage: " << prog << L"[options] <logfile>*\n"
    << L"A specialized trace viewer to interpret trace logs captured\n"
    << L"with the CallTrace DLL.\n"
    << L"Available options:\n"
    << L"  --session: the name of a realtime trace session to consume\n"
    << L"  --print_call_trace: dumps the stack trace for every call site\n"
    << L"  --print_args: dumps the argument words for every call site\n"
    << L"  --print_retval: dumps the return value word for every call site\n"
    << L"  --only_process: only display events for this process id\n"
    << L"  --only_thread: only display events for this thread id";

  return 1;
}

int wmain(int argc, wchar_t** argv) {
  base::AtExitManager at_exit;
  CommandLine::Init(0, NULL);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  if (cmd_line->HasSwitch("help") || cmd_line->HasSwitch("h"))
    return Usage(argv[0]);

  // Parse the arguments we care about.
  bool print_call_trace = cmd_line->HasSwitch("print_call_trace");
  bool print_args = cmd_line->HasSwitch("print_args");
  bool print_retval = cmd_line->HasSwitch("print_retval");

  int only_process = StringToInt(cmd_line->GetSwitchValue("only_process"));
  int only_thread = StringToInt(cmd_line->GetSwitchValue("only_thread"));

  std::wstring session = cmd_line->GetSwitchValue("session");
  typedef std::vector<std::wstring> StringVector;
  StringVector files = cmd_line->GetLooseValues();
  if (session.empty() && files.empty()) {
    return Usage(argv[0]);
  }

  ViewerTraceConsumer consumer(print_call_trace,
                               print_args,
                               print_retval,
                               only_process,
                               only_thread);

  if (!session.empty()) {
    HRESULT hr = consumer.OpenRealtimeSession(session.c_str());
    std::wcout << "Failed to open realtime session \"" << session
        << "\", error: " << hr << std::endl;
    return hr;
  }

  for (StringVector::iterator it = files.begin(); it < files.end(); ++it) {
    HRESULT hr = consumer.OpenFileSession(it->c_str());
    if (FAILED(hr)) {
      std::wcout << "Failed to open file \"" << *it << "\", error: "
          << hr << std::endl;

      return hr;
    }
  }

  HRESULT hr = consumer.Consume();
  return hr;
}
