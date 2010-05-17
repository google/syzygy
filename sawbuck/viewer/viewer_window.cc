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
// Log viewer window implementation.
#include "sawbuck/viewer/viewer_window.h"

#include "pcrecpp.h"  // NOLINT
#include "base/basictypes.h"
#include "base/event_trace_consumer_win.h"
#include "base/file_util.h"
#include "base/string_util.h"
#include "base/logging.h"
#include "sawbuck/sym_util/symbol_cache.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/provider_dialog.h"
#include "sawbuck/viewer/viewer_module.h"
#include <initguid.h>  // NOLINT

namespace {

// We know the lifetime of the ViewerWindow exceeds the worker threads,
// so noop for retain is safe for the ViewerWindow.
template <>
struct RunnableMethodTraits<ViewerWindow> {
  void RetainCallee(ViewerWindow* window) {
  }

  void ReleaseCallee(ViewerWindow* window) {
  }
};

template <>
struct RunnableMethodTraits<LogConsumer> {
  void RetainCallee(LogConsumer* window) {
  }

  void ReleaseCallee(LogConsumer* window) {
  }
};

template <>
struct RunnableMethodTraits<KernelLogConsumer> {
  void RetainCallee(KernelLogConsumer* window) {
  }

  void ReleaseCallee(KernelLogConsumer* window) {
  }
};

// A regular expression that matches "[<stuff>:<file>(<line>)].message"
// and extracts the file/line/message parts.
const pcrecpp::RE kFileRe("\\[[^\\]]*\\:([^:]+)\\((\\d+)\\)\\].(.*\\w).*",
                          PCRE_NEWLINE_ANYCRLF | PCRE_DOTALL | PCRE_UTF8);

const wchar_t kSessionName[] = L"Sawbuck Log Session";

bool Is64BitSystem() {
  if (sizeof(void*) == 8)  // NOLINT
    return true;

  HMODULE kernel32 = ::GetModuleHandle(L"kernel32.dll");
  if (!kernel32)
    return false;

  typedef BOOL (WINAPI* IsWow64ProcessProc)(HANDLE process, PBOOL is_wow64);
  IsWow64ProcessProc is_wow_64_process =
      reinterpret_cast<IsWow64ProcessProc>(
          ::GetProcAddress(kernel32, "IsWow64Process"));

  if (is_wow_64_process == NULL)
    return false;

  BOOL is_wow_64 = FALSE;
  CHECK(IsWow64Process(::GetCurrentProcess(), &is_wow_64));

  return is_wow_64 != FALSE;
}

}  // namespace

bool operator < (const GUID& a, const GUID& b) {
  return 0 < memcmp(&a, &b, sizeof(a));
}

void ViewerWindow::CompileAsserts() {
}

ViewerWindow::ViewerWindow()
     : notify_log_view_new_items_(NULL),
       symbol_lookup_worker_("Symbol Lookup Worker"),
       next_sink_cookie_(1),
       update_status_task_(NULL),
       log_viewer_(this),
       ui_loop_(NULL),
       log_consumer_thread_("Event log consumer"),
       kernel_consumer_thread_("Kernel log consumer") {
  ui_loop_ = MessageLoop::current();
  DCHECK(ui_loop_ != NULL);

  symbol_lookup_worker_.Start();
  DCHECK(symbol_lookup_worker_.message_loop() != NULL);

  status_callback_.reset(NewCallback(this, &ViewerWindow::OnStatusUpdate));
  symbol_lookup_service_.set_status_callback(status_callback_.get());

  symbol_lookup_service_.set_background_thread(
      symbol_lookup_worker_.message_loop());

  ReadProviderSettings(&settings_);
}

ViewerWindow::~ViewerWindow() {
  // Last resort..
  StopCapturing();

  symbol_lookup_worker_.Stop();

  if (notify_log_view_new_items_ != NULL) {
    notify_log_view_new_items_->Cancel();
    notify_log_view_new_items_ = NULL;
  }
}

namespace {

class ImportLogConsumer
    : public EtwTraceConsumerBase<ImportLogConsumer>,
      public LogParser,
      public KernelLogParser {
 public:
  ImportLogConsumer();
  ~ImportLogConsumer();

  static void ProcessEvent(PEVENT_TRACE event);

 private:
  static ImportLogConsumer* current_;
};

ImportLogConsumer* ImportLogConsumer::current_ = NULL;

ImportLogConsumer::ImportLogConsumer() {
  DCHECK(current_ == NULL);
  current_ = this;
}

ImportLogConsumer::~ImportLogConsumer() {
  DCHECK(current_ == this);
  current_ = NULL;
}

void ImportLogConsumer::ProcessEvent(PEVENT_TRACE event) {
  DCHECK(current_ != NULL);

  if (!current_->LogParser::ProcessOneEvent(event) &&
      !current_->KernelLogParser::ProcessOneEvent(event)) {
    LOG(INFO) << "Unknown event";
  }
}

}  // namespace

void ViewerWindow::ImportLogFiles(const std::vector<FilePath>& paths) {
  UISetText(0, L"Importing");
  UIUpdateStatusBar();

  ImportLogConsumer import_consumer;

  // Open all the log files.
  for (size_t i = 0; i < paths.size(); ++i) {
    HRESULT hr = import_consumer.OpenFileSession(paths[i].value().c_str());

    if (FAILED(hr)) {
      std::wstring msg =
          StringPrintf(L"Failed to open log file \"%ls\", error 0x%08X",
                       paths[i].value().c_str(),
                       hr);

      ::MessageBox(m_hWnd, msg.c_str(), L"Error Importing Logs", MB_OK);
      return;
    }
  }

  // Attach our event sinks to the consumer.
  import_consumer.set_event_sink(this);
  import_consumer.set_trace_sink(this);
  import_consumer.set_process_event_sink(&process_info_service_);
  import_consumer.set_module_event_sink(&symbol_lookup_service_);

  // Consume the files.
  // TODO(siggi): Report progress here.
  HRESULT hr = import_consumer.Consume();
  if (FAILED(hr)) {
    std::wstring msg =
        StringPrintf(L"Import failed with error 0x%08X",
                     hr);
    ::MessageBox(m_hWnd, msg.c_str(), L"Error Importing Logs", MB_OK);
  }

  UISetText(0, L"Ready");
}

const wchar_t kLogFileFilter[] =
    L"Event Trace Files\0*.etl\0"
    L"All Files\n\0*.*\0";

void ViewerWindow::SetCapture(bool capture) {
  bool capturing = (log_controller_.session() != NULL);
  if (capturing != capture) {
    if (capture) {
      if (!StartCapturing()) {
        capture = false;
        StopCapturing();
      }
    } else {
      StopCapturing();
    }
  }

  // Only allow import when not capturing.
  UIEnable(ID_FILE_IMPORT, !capture);
  UISetCheck(ID_LOG_CAPTURE, capture);
}

LRESULT ViewerWindow::OnImport(
    WORD code, LPARAM lparam, HWND wnd, BOOL& handled) {
  CMultiFileDialog dialog(NULL, NULL, 0, kLogFileFilter, m_hWnd);

  if (dialog.DoModal() == IDOK) {
    std::vector<FilePath> paths;

    std::wstring path;
    int len = dialog.GetFirstPathName(NULL, 0);
    DCHECK(len != 0);
    path.resize(len);
    len = dialog.GetFirstPathName(&path[0], path.size());
    DCHECK(len != 0);

    do {
      paths.push_back(FilePath(path));

      len = dialog.GetNextPathName(NULL, 0);
      if (len != 0) {
        path.resize(len);
        len = dialog.GetNextPathName(&path[0], path.size());
      }
    } while (len != 0);

    ImportLogFiles(paths);
  }

  return 0;
}

LRESULT ViewerWindow::OnExit(
    WORD code, LPARAM lparam, HWND wnd, BOOL& handled) {
  PostMessage(WM_CLOSE);
  return 0;
}

LRESULT ViewerWindow::OnAbout(
    WORD code, LPARAM lparam, HWND wnd, BOOL& handled) {
  CSimpleDialog<IDD_ABOUT> dialog;
  dialog.DoModal(m_hWnd);
  return 0;
}

void ViewerWindow::StopCapturing() {
  log_controller_.Stop(NULL);
  kernel_controller_.Stop(NULL);
  log_consumer_thread_.Stop();
  log_consumer_.reset();

  kernel_consumer_thread_.Stop();
  kernel_consumer_.reset();
}

static bool TestAndOfferToStopSession(HWND parent,
                                      const wchar_t* session_name) {
  // Try and query the session properties.
  // This can only succeed if the session exists.
  EtwTraceProperties props;
  HRESULT hr = EtwTraceController::Query(session_name, &props);
  if (SUCCEEDED(hr)) {
    std::wstring str;
    str = StringPrintf(L"The log trace session \"%ls\" is already in use. "
        L"You may have another copy of Sawbuck running already, or some other "
        L"application may be using the session, or (shudder) Sawbuck may have "
        L"crashed previously.\n"
        L"Press OK to close the session and start capturing.",
            session_name);

    int result = ::MessageBox(parent,
                              str.c_str(),
                              L"Trace Session in use",
                              MB_OKCANCEL);

    if (result == IDOK) {
      // User pressed OK, attempt to stop the session.
      hr = EtwTraceController::Stop(session_name, &props);
      if (FAILED(hr)) {
        str = StringPrintf(L"Failed to stop trace session \"%ls\".",
                           session_name);
        ::MessageBox(parent, str.c_str(), L"Error", MB_OK);
        return false;
      }
    } else {
      // User cancelled.
      return false;
    }
  }

  return true;
}

bool ViewerWindow::StartCapturing() {
  DCHECK(NULL == log_controller_.session());
  DCHECK(NULL == kernel_controller_.session());
  DCHECK(NULL == log_consumer_.get());
  DCHECK(NULL == kernel_consumer_.get());

  // Preflight the start operation by seeing whether one of the log sessions
  // we're going to establish are already in use, and offer to stop them if so.
  if (!TestAndOfferToStopSession(m_hWnd, kSessionName) ||
      !TestAndOfferToStopSession(m_hWnd, KERNEL_LOGGER_NAME)) {
    // One or both log sessions still in use.
    return false;
  }

  // Open a session for our log message capturing.
  HRESULT hr = log_controller_.StartRealtimeSession(kSessionName, 1024);
  if (FAILED(hr))
    return false;

  // And open a consumer on it.
  log_consumer_.reset(new LogConsumer());
  log_consumer_->set_event_sink(this);
  log_consumer_->set_trace_sink(this);
  hr = log_consumer_->OpenRealtimeSession(kSessionName);
  if (FAILED(hr))
    return false;

  // Consume it in a new thread.
  CHECK(log_consumer_thread_.Start());
  log_consumer_thread_.message_loop()->PostTask(FROM_HERE,
      NewRunnableMethod(log_consumer_.get(), &LogConsumer::Consume));

  // Start the kernel logger session.
  EtwTraceProperties prop;
  EVENT_TRACE_PROPERTIES* p = prop.get();
  p->Wnode.Guid = SystemTraceControlGuid;
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->MaximumFileSize = 100;  // 100 M file size.
  // Get image load and process events.
  p->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_PROCESS;
  p->FlushTimer = 1;  // flush every second.
  p->BufferSize = 16;  // 16 K buffers.
  hr = kernel_controller_.Start(KERNEL_LOGGER_NAME, &prop);
  if (FAILED(hr))
    return false;

  // And open a consumer on it.
  kernel_consumer_.reset(new KernelLogConsumer());
  DCHECK(NULL != kernel_consumer_.get());
  kernel_consumer_->set_module_event_sink(&symbol_lookup_service_);
  kernel_consumer_->set_process_event_sink(&process_info_service_);
  kernel_consumer_->set_is_64_bit_log(Is64BitSystem());
  hr = kernel_consumer_->OpenRealtimeSession(KERNEL_LOGGER_NAME);
  if (FAILED(hr))
    return false;

  // Consume it in a new thread.
  CHECK(kernel_consumer_thread_.Start());
  kernel_consumer_thread_.message_loop()->PostTask(FROM_HERE,
      NewRunnableMethod(kernel_consumer_.get(), &KernelLogConsumer::Consume));

  if (SUCCEEDED(hr))
    EnableProviders(settings_);

  return SUCCEEDED(hr);
}

void ViewerWindow::EnableProviders(
    const ProviderSettingsList& settings) {
  for (size_t i = 0; i < settings.size(); ++i) {
    log_controller_.EnableProvider(
        settings[i].provider_guid, settings[i].log_level);
  }
}

void ViewerWindow::OnLogMessage(const LogEvents::LogMessage& log_message) {
  ViewerWindow::LogMessage msg;
  msg.level = log_message.level;
  msg.process_id = log_message.process_id;
  msg.thread_id = log_message.thread_id;
  msg.time_stamp = log_message.time;

  // Use regular expression matching to extract the
  // file/line/message from the log string, which is of
  // format "[<stuff>:<file>(<line>)] <message><ws>".
  if (!kFileRe.FullMatch(
      pcrecpp::StringPiece(log_message.message, log_message.message_len),
                           &msg.file, &msg.line, &msg.message)) {
    // As fallback, just slurp the entire string.
    msg.message.assign(log_message.message, log_message.message_len);
  }

  for (size_t i = 0; i < log_message.trace_depth; ++i)
    msg.trace.push_back(log_message.traces[i]);

  AutoLock lock(list_lock_);
  log_messages_.push_back(msg);

  ScheduleNewItemsNotification();
}

void ViewerWindow::OnStatusUpdate(const wchar_t* status) {
  AutoLock lock(status_lock_);
  if (status_.find_first_of(L"\r\n") == std::wstring::npos) {
    // No EOL in current status, backup for every backspace char.
    for (; *status != L'\0'; ++status) {
      const wchar_t kBackSpace = 0x08;
      if (*status == 0x08) {
        if (status_.length() > 0)
          status_.resize(status_.length() - 1);
      } else {
        status_ += *status;
      }
    }
  } else {
    // EOL in current status, just replace it.
    status_ = status;
  }

  // Post a task to update the status on the UI thread, unless
  // there's a task already pending.
  if (update_status_task_ == NULL) {
    update_status_task_ = NewRunnableMethod(this,
                                           &ViewerWindow::UpdateStatus);
    if (update_status_task_ != NULL)
      ui_loop_->PostTask(FROM_HERE, update_status_task_);
  }
}

void ViewerWindow::UpdateStatus() {
  DCHECK_EQ(MessageLoop::current(), ui_loop_);

  AutoLock lock(status_lock_);
  update_status_task_ = NULL;
  UISetText(0, status_.c_str());
}

void ViewerWindow::OnTraceEventBegin(
    const TraceEvents::TraceMessage& trace_message) {
  AddTraceEventToLog("BEGIN", trace_message);
}

void ViewerWindow::OnTraceEventEnd(
    const TraceEvents::TraceMessage& trace_message) {
  AddTraceEventToLog("END", trace_message);
}

void ViewerWindow::OnTraceEventInstant(
    const TraceEvents::TraceMessage& trace_message) {
  AddTraceEventToLog("INSTANT", trace_message);
}

void ViewerWindow::AddTraceEventToLog(const char* type,
    const TraceEvents::TraceMessage& trace_message) {
  ViewerWindow::LogMessage msg;
  msg.level = trace_message.level;
  msg.process_id = trace_message.process_id;
  msg.thread_id = trace_message.thread_id;
  msg.time_stamp = trace_message.time;

  // The message will be of form "{BEGIN|END|INSTANT}(<name>, 0x<id>): <extra>"
  msg.message = StringPrintf("%s(%*s, 0x%08X): %*s",
                             type,
                             trace_message.name_len,
                             trace_message.name,
                             trace_message.id,
                             trace_message.extra_len,
                             trace_message.extra);

  for (size_t i = 0; i < trace_message.trace_depth; ++i)
    msg.trace.push_back(trace_message.traces[i]);

  AutoLock lock(list_lock_);
  log_messages_.push_back(msg);

  ScheduleNewItemsNotification();
}

void ViewerWindow::ScheduleNewItemsNotification() {
  // The list lock must be held.
  list_lock_.AssertAcquired();

  if (notify_log_view_new_items_ == NULL) {
    notify_log_view_new_items_ =
        NewRunnableMethod(this, &ViewerWindow::NotifyLogViewNewItems);
    DCHECK(notify_log_view_new_items_ != NULL);

    if (notify_log_view_new_items_ != NULL) {
      ui_loop_->PostTask(FROM_HERE, notify_log_view_new_items_ );
    }
  }
}

void ViewerWindow::NotifyLogViewNewItems() {
  DCHECK_EQ(ui_loop_, MessageLoop::current());
  {
    AutoLock lock(list_lock_);

    // Notification no longer pending.
    notify_log_view_new_items_ = NULL;
  }

  EventSinkMap::iterator it(event_sinks_.begin());
  for (; it != event_sinks_.end(); ++it) {
    it->second->LogViewNewItems();
  }
}

void ViewerWindow::NotifyLogViewCleared() {
  DCHECK_EQ(ui_loop_, MessageLoop::current());
  EventSinkMap::iterator it(event_sinks_.begin());
  for (; it != event_sinks_.end(); ++it) {
    it->second->LogViewCleared();
  }
}

LRESULT ViewerWindow::OnConfigureProviders(WORD code,
                                           LPARAM lparam,
                                           HWND wnd,
                                           BOOL& handled) {
  // Make a copy of our settings.
  ProviderSettingsList settings(settings_);
  ProviderDialog dialog(settings.size(),
                        settings.size() ? &settings[0] : NULL);
  if (dialog.DoModal(m_hWnd) == IDOK) {
    settings_ = settings;
    EnableProviders(settings_);
    WriteProviderSettings(settings_);
  }

  return 0;
}

LRESULT ViewerWindow::OnToggleCapture(WORD code,
                                      LPARAM lparam,
                                      HWND wnd,
                                      BOOL& handled) {
  bool capturing = log_controller_.session() != NULL;
  DCHECK_EQ(capturing,
            ((UIGetState(ID_LOG_CAPTURE) & UPDUI_CHECKED) == UPDUI_CHECKED));
  SetCapture(!capturing);

  return 0;
}

BOOL ViewerWindow::OnIdle() {
  UIUpdateMenuBar();
  UIUpdateStatusBar();

  return TRUE;
}

BOOL ViewerWindow::PreTranslateMessage(MSG* msg) {
  return SuperFrame::PreTranslateMessage(msg);
}

int ViewerWindow::OnCreate(LPCREATESTRUCT lpCreateStruct) {
  // TODO(siggi): Make the toolbar useful.
  // CreateSimpleToolBar();

  // Import is enabled, except when capturing.
  UIEnable(ID_FILE_IMPORT, true);

  // Edit menu is disabled by default.
  UIEnable(ID_EDIT_CUT, false);
  UIEnable(ID_EDIT_COPY, false);
  UIEnable(ID_EDIT_PASTE, false);
  UIEnable(ID_EDIT_CLEAR, false);
  UIEnable(ID_EDIT_CLEAR_ALL, false);
  UIEnable(ID_EDIT_SELECT_ALL, false);

  CreateSimpleStatusBar();
  UIAddStatusBar(m_hWndStatusBar);

  // Set the main window title.
  SetWindowText(L"Sawbuck Log Viewer");

  log_viewer_.SetLogView(this);
  log_viewer_.SetSymbolLookupService(&symbol_lookup_service_);
  log_viewer_.SetProcessInfoService(&process_info_service_);

  log_viewer_.Create(m_hWnd,
                     NULL,
                     NULL,
                     WS_VISIBLE | WS_CHILDWINDOW | WS_CLIPCHILDREN,
                     WS_EX_CLIENTEDGE);

  // Set the list view as the client view.
  m_hWndClient = log_viewer_;

  // Retrieve our placement from registry if available, and
  // place our window to the last saved placement if so.
  CRegKey key;
  ULONG err = key.Open(HKEY_CURRENT_USER, config::kSettingsKey);
  if (err == ERROR_SUCCESS) {
    WINDOWPLACEMENT placement = { 0 };
    ULONG size = sizeof(placement);
    err = key.QueryBinaryValue(config::kWindowPosValue, &placement, &size);
    if (err == ERROR_SUCCESS && size == sizeof(placement)) {
      // If we were closed invisible, minimized, or any other weird show state,
      // we don't want to get back in that state. Force normal or maximized.
      if (placement.showCmd != SW_SHOWNORMAL &&
          placement.showCmd != SW_SHOWMAXIMIZED) {
        placement.showCmd = SW_SHOWNORMAL;
      }
      SetWindowPlacement(&placement);
    }
  }

  UpdateLayout();
  UIAddMenuBar(m_hWnd);

  CMessageLoop* loop = g_sawbuck_app_module.GetMessageLoop();
  DCHECK(loop != NULL);
  loop->AddMessageFilter(this);
  loop->AddIdleHandler(this);

  return 0;
}

void ViewerWindow::OnDestroy() {
  // Get our Window placement and stash it in registry.
  WINDOWPLACEMENT placement = { sizeof(placement) };
  if (GetWindowPlacement(&placement)) {
    CRegKey key;

    ULONG err = key.Create(HKEY_CURRENT_USER, config::kSettingsKey);
    if (err == ERROR_SUCCESS)
      key.SetBinaryValue(config::kWindowPosValue,
                         &placement,
                         sizeof(placement));
  }

  // Wind up this program.
  ::PostQuitMessage(1);
}

int ViewerWindow::GetNumRows() {
  AutoLock lock(list_lock_);
  return log_messages_.size();
}

void ViewerWindow::ClearAll() {
  {
    AutoLock lock(list_lock_);
    log_messages_.clear();
  }
  NotifyLogViewCleared();
}

int ViewerWindow::GetSeverity(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].level;
}

DWORD ViewerWindow::GetProcessId(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].process_id;
}

DWORD ViewerWindow::GetThreadId(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].thread_id;
}

base::Time ViewerWindow::GetTime(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].time_stamp;
}

std::string ViewerWindow::GetFileName(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].file;
}

int ViewerWindow::GetLine(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].line;
}

std::string ViewerWindow::GetMessage(int row) {
  AutoLock lock(list_lock_);
  return log_messages_[row].message;
}

void ViewerWindow::GetStackTrace(int row, std::vector<void*>* trace) {
  AutoLock lock(list_lock_);
  *trace = log_messages_[row].trace;
}

void ViewerWindow::Register(ILogViewEvents* event_sink,
                            int* registration_cookie) {
  int cookie = next_sink_cookie_++;

  event_sinks_.insert(std::make_pair(cookie, event_sink));
  *registration_cookie = cookie;
}

void ViewerWindow::Unregister(int registration_cookie) {
  event_sinks_.erase(registration_cookie);
}

void ViewerWindow::ReadProviderSettings(
    ProviderSettingsList* settings) {
  // Storage for the GUID->name mapping.
  typedef std::map<GUID, std::wstring> ProviderNamesMap;
  ProviderNamesMap provider_names;

  CRegKey providers;
  LONG err = providers.Open(HKEY_LOCAL_MACHINE,
                            config::kProviderNamesKey,
                            KEY_READ);
  if (err != ERROR_SUCCESS) {
    LOG(ERROR) << "Failed to open provider names key";
    return;
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

    GUID provider_name = {};
    if (FAILED(::CLSIDFromString(tmp_string, &provider_name))) {
      LOG(ERROR) << "Non-GUID provider \"" << tmp_string << "\"";
      continue;
    }

    CRegKey subkey;
    err = subkey.Open(providers, tmp_string);
    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error opening provider key " << tmp_string << ", " << err;
      continue;
    }

    tmp_len = arraysize(tmp_string);
    err = subkey.QueryStringValue(NULL, tmp_string, &tmp_len);
    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Error reading provider name " << err;
      continue;
    }

    provider_names.insert(std::make_pair(provider_name, tmp_string));
  }

  settings->clear();

  // Read the provider names from registry, and attempt to read
  // the trace level for each, defaulting to INFO.
  CRegKey levels_key;
  LONG error = levels_key.Open(HKEY_CURRENT_USER, config::kProviderLevelsKey);

  ProviderNamesMap::const_iterator it(provider_names.begin());
  for (; it != provider_names.end(); ++it) {
    ProviderSettings setting;
    setting.log_level = TRACE_LEVEL_INFORMATION;
    setting.provider_guid = it->first;
    setting.provider_name = it->second;

    if (levels_key != NULL) {
      wchar_t value_name[40] = {};
      CHECK(::StringFromGUID2(setting.provider_guid,
                              value_name,
                              arraysize(value_name)));
      DWORD log_level = 0;
      error = levels_key.QueryDWORDValue(value_name, log_level);
      if (error == ERROR_SUCCESS)
        setting.log_level = static_cast<UCHAR>(log_level);
    }

    settings->push_back(setting);
  }
}

void ViewerWindow::WriteProviderSettings(
    const ProviderSettingsList& settings) {
  CRegKey levels_key;
  LONG error = levels_key.Create(HKEY_CURRENT_USER,
                                 config::kProviderLevelsKey,
                                 0,
                                 0,
                                 KEY_WRITE);
  if (error != ERROR_SUCCESS) {
    LOG(ERROR) << "Error saving provider log levels: " << error;

    return;
  }

  for (size_t i = 0; i < settings.size(); ++i) {
    wchar_t value_name[40] = {};
    CHECK(::StringFromGUID2(settings[i].provider_guid,
                            value_name,
                            arraysize(value_name)));

    error = levels_key.SetDWORDValue(value_name, settings[i].log_level);
    if (error != ERROR_SUCCESS)
      LOG(ERROR) << "Error writing log level for provider " <<
          settings[i].provider_name << ", error: " << error;
  }
}
