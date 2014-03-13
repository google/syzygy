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
// Log viewer window implementation.
#include "sawbuck/viewer/viewer_window.h"

#include "pcrecpp.h"  // NOLINT
#include "base/bind.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/event_trace_consumer.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/preferences.h"
#include "sawbuck/viewer/provider_dialog.h"
#include "sawbuck/viewer/viewer_module.h"
#include <initguid.h>  // NOLINT

namespace {

const wchar_t* kMicrosoftSymSrv = L"http://msdl.microsoft.com/download/symbols";
const wchar_t* kChromeSymSrv =
    L"http://chromium-browser-symsrv.commondatastorage.googleapis.com";

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
     : symbol_lookup_worker_("Symbol Lookup Worker"),
       next_sink_cookie_(1),
       log_viewer_(this),
       ui_loop_(NULL),
       notify_log_view_new_items_(
          base::Bind(&ViewerWindow::NotifyLogViewNewItems,
                     base::Unretained(this))),
       notify_log_view_new_items_pending_(false),
       update_status_task_(base::Bind(&ViewerWindow::UpdateStatus,
                                      base::Unretained(this))),
       update_status_task_pending_(false),
       log_consumer_thread_("Event log consumer"),
       kernel_consumer_thread_("Kernel log consumer") {
  ui_loop_ = MessageLoop::current();
  DCHECK(ui_loop_ != NULL);

  symbol_lookup_worker_.Start();
  DCHECK(symbol_lookup_worker_.message_loop() != NULL);

  status_callback_ = base::Bind(&ViewerWindow::OnStatusUpdate,
                                base::Unretained(this));
  symbol_lookup_service_.set_status_callback(status_callback_);

  symbol_lookup_service_.set_background_thread(
      symbol_lookup_worker_.message_loop());

  InitSymbolPath();
  symbol_lookup_service_.SetSymbolPath(symbol_path_.c_str());

  settings_.ReadProviders();
  settings_.ReadSettings();
}

ViewerWindow::~ViewerWindow() {
  // Last resort..
  StopCapturing();

  symbol_lookup_worker_.Stop();

  notify_log_view_new_items_.Cancel();
  update_status_task_.Cancel();
}

namespace {

class ImportLogConsumer
    : public base::win::EtwTraceConsumerBase<ImportLogConsumer>,
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

void ViewerWindow::ImportLogFiles(const std::vector<base::FilePath>& paths) {
  UISetText(0, L"Importing");
  UIUpdateStatusBar();

  ImportLogConsumer import_consumer;

  // Open all the log files.
  for (size_t i = 0; i < paths.size(); ++i) {
    HRESULT hr = import_consumer.OpenFileSession(paths[i].value().c_str());

    if (FAILED(hr)) {
      std::wstring msg =
          base::StringPrintf(L"Failed to open log file \"%ls\", error 0x%08X",
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
        base::StringPrintf(L"Import failed with error 0x%08X", hr);
    ::MessageBox(m_hWnd, msg.c_str(), L"Error Importing Logs", MB_OK);
  }

  UISetText(0, L"Ready");
  UIUpdateStatusBar();
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
    std::vector<base::FilePath> paths;

    std::wstring path;
    int len = dialog.GetFirstPathName(NULL, 0);
    DCHECK(len != 0);
    path.resize(len);
    len = dialog.GetFirstPathName(&path[0], path.size());
    DCHECK(len != 0);

    do {
      paths.push_back(base::FilePath(path));

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
  base::win::EtwTraceProperties props;
  HRESULT hr = base::win::EtwTraceController::Query(session_name, &props);
  if (SUCCEEDED(hr)) {
    std::wstring str;
    str = base::StringPrintf(
        L"The log trace session \"%ls\" is already in use. "
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
      hr = base::win::EtwTraceController::Stop(session_name, &props);
      if (FAILED(hr)) {
        str = base::StringPrintf(L"Failed to stop trace session \"%ls\".",
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

  // Create a session for our log message capturing.
  base::win::EtwTraceProperties log_props;
  EVENT_TRACE_PROPERTIES* p = log_props.get();
  // Use the QPC timer, see
  // http://msdn.microsoft.com/en-us/library/aa364160(v=vs.85).aspx.
  p->Wnode.ClientContext = 1;
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->MaximumFileSize = 100;  // 100 M file size.
  // Get image load and process events.
  p->FlushTimer = 1;  // flush every second.
  p->BufferSize = 16;  // 16 K buffers.
  HRESULT hr = log_controller_.Start(kSessionName, &log_props);
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
      base::Bind(base::IgnoreResult(&LogConsumer::Consume),
                 base::Unretained(log_consumer_.get())));

  // Start the kernel logger session.
  base::win::EtwTraceProperties kernel_props;
  p = kernel_props.get();
  p->Wnode.Guid = SystemTraceControlGuid;
  // Use the QPC timer, see
  // http://msdn.microsoft.com/en-us/library/aa364160(v=vs.85).aspx.
  p->Wnode.ClientContext = 1;
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->MaximumFileSize = 100;  // 100 M file size.
  // Get image load and process events.
  p->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_PROCESS;
  p->FlushTimer = 1;  // flush every second.
  p->BufferSize = 16;  // 16 K buffers.
  hr = kernel_controller_.Start(KERNEL_LOGGER_NAME, &kernel_props);
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
      base::Bind(base::IgnoreResult(&KernelLogConsumer::Consume),
                 base::Unretained(kernel_consumer_.get())));

  if (SUCCEEDED(hr))
    EnableProviders(settings_);

  return SUCCEEDED(hr);
}

void ViewerWindow::EnableProviders(
    const ProviderConfiguration& settings) {
  for (size_t i = 0; i < settings.settings().size(); ++i) {
    log_controller_.EnableProvider(
        settings.settings()[i].provider_guid,
        settings.settings()[i].log_level,
        settings.settings()[i].enable_flags);
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

  // If the message carried file information, use that
  // in preference to the above.
  if (log_message.file_len != 0) {
    msg.file.assign(log_message.file, log_message.file_len);
    msg.line = log_message.line;
  }

  if (log_message.trace_depth > 0) {
    msg.trace.insert(msg.trace.begin(),
                     &log_message.traces[0],
                     &log_message.traces[log_message.trace_depth - 1]);
  }

  base::AutoLock lock(list_lock_);
  log_messages_.push_back(msg);

  ScheduleNewItemsNotification();
}

void ViewerWindow::OnStatusUpdate(const wchar_t* status) {
  base::AutoLock lock(status_lock_);
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
  if (!update_status_task_pending_) {
    update_status_task_pending_ = true;
    ui_loop_->PostTask(FROM_HERE, update_status_task_.callback());
  }
}

void ViewerWindow::UpdateStatus() {
  DCHECK_EQ(MessageLoop::current(), ui_loop_);

  std::wstring status;
  {
    base::AutoLock lock(status_lock_);
    update_status_task_pending_ = false;
    status = status_;
  }

  UISetText(0, status.c_str());
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
  msg.message = base::StringPrintf("%s(%*s, 0x%08X): %*s",
                                   type,
                                   trace_message.name_len,
                                   trace_message.name,
                                   trace_message.id,
                                   trace_message.extra_len,
                                   trace_message.extra);

  for (size_t i = 0; i < trace_message.trace_depth; ++i)
    msg.trace.push_back(trace_message.traces[i]);

  base::AutoLock lock(list_lock_);
  log_messages_.push_back(msg);

  ScheduleNewItemsNotification();
}

void ViewerWindow::ScheduleNewItemsNotification() {
  // The list lock must be held.
  list_lock_.AssertAcquired();

  if (!notify_log_view_new_items_pending_) {
    notify_log_view_new_items_pending_ = true;
    ui_loop_->PostTask(FROM_HERE, notify_log_view_new_items_.callback());
  }
}

void ViewerWindow::NotifyLogViewNewItems() {
  DCHECK_EQ(ui_loop_, MessageLoop::current());
  {
    base::AutoLock lock(list_lock_);

    // Notification no longer pending.
    notify_log_view_new_items_pending_ = false;
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
  ProviderConfiguration settings_copy;

  settings_copy.Copy(settings_);

  ProviderDialog dialog(&settings_copy);
  if (dialog.DoModal(m_hWnd) == IDOK) {
    settings_.Copy(settings_copy);
    EnableProviders(settings_);
    settings_.WriteSettings();
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

namespace {

class SymbolPathDialog: public CDialogImpl<SymbolPathDialog> {
 public:
  BEGIN_MSG_MAP(SymbolPathDialog)
    MSG_WM_INITDIALOG(OnInitDialog)
    COMMAND_RANGE_HANDLER(IDOK, IDNO, OnCloseCmd)
  END_MSG_MAP()

  static const int IDD = IDD_SYMBOLPATH;

  explicit SymbolPathDialog(std::wstring* symbol_path)
      : symbol_path_(symbol_path) {
    DCHECK(symbol_path != NULL);
  }

 private:
  BOOL OnInitDialog(CWindow focus, LPARAM init_param) {
    SetDlgItemText(IDC_SYMBOLPATH, symbol_path_->c_str());
    CenterWindow(GetParent());
    return TRUE;
  }

  LRESULT OnCloseCmd(WORD code, WORD id, HWND ctl, BOOL& handled) {
    ::EndDialog(m_hWnd, id);

    // Stash the new symbol path to the string we were handed on IDOK.
    HWND item = GetDlgItem(IDC_SYMBOLPATH);
    if (id == IDOK && item != NULL) {
      int length = ::GetWindowTextLength(item);
      symbol_path_->resize(length);
      length = ::GetWindowText(item, &(*symbol_path_)[0], length + 1);
      symbol_path_->resize(length);
    }

    return 0;
  }

  std::wstring* symbol_path_;
};

}  // namespace

LRESULT ViewerWindow::OnSymbolPath(WORD code,
                                   LPARAM lparam,
                                   HWND wnd,
                                   BOOL& handled) {
  SymbolPathDialog dialog(&symbol_path_);

  if (IDOK == dialog.DoModal(m_hWnd)) {
    Preferences pref;
    pref.WriteStringValue(config::kSymPathValue, symbol_path_);

    symbol_lookup_service_.SetSymbolPath(symbol_path_.c_str());
  }

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
  UIEnable(ID_EDIT_FIND, false);
  UIEnable(ID_EDIT_FIND_NEXT, false);

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
  base::AutoLock lock(list_lock_);
  return log_messages_.size();
}

void ViewerWindow::ClearAll() {
  {
    base::AutoLock lock(list_lock_);
    log_messages_.clear();
  }
  NotifyLogViewCleared();
}

int ViewerWindow::GetSeverity(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].level;
}

DWORD ViewerWindow::GetProcessId(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].process_id;
}

DWORD ViewerWindow::GetThreadId(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].thread_id;
}

base::Time ViewerWindow::GetTime(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].time_stamp;
}

std::string ViewerWindow::GetFileName(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].file;
}

int ViewerWindow::GetLine(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].line;
}

std::string ViewerWindow::GetMessage(int row) {
  base::AutoLock lock(list_lock_);
  return log_messages_[row].message;
}

void ViewerWindow::GetStackTrace(int row, std::vector<void*>* trace) {
  base::AutoLock lock(list_lock_);
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

void ViewerWindow::InitSymbolPath() {
  {
    // Attempt to read our current preference if one exists.
    Preferences pref;
    if (pref.ReadStringValue(config::kSymPathValue, &symbol_path_, NULL))
      return;
  }

  // No preference, see if there's a fallback in the environment.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  std::string nt_symbol_path;
  if (!env.get() || !env->GetVar("_NT_SYMBOL_PATH", &nt_symbol_path)) {
    // We have no symbol path, make one up!
    base::FilePath temp_dir;
    if (!PathService::Get(base::DIR_TEMP, &temp_dir))
      return;

    base::FilePath sym_dir(temp_dir.Append(L"symbols"));
    if (!file_util::CreateDirectory(sym_dir))
      return;

    symbol_path_ =
        base::StringPrintf(L"SRV*%ls*%ls;SRV*%ls*%ls",
                           sym_dir.value().c_str(),
                           kMicrosoftSymSrv,
                           sym_dir.value().c_str(),
                           kChromeSymSrv);

    // Write the newly fabricated path to our preferences.
    Preferences pref;
    pref.WriteStringValue(config::kSymPathValue, symbol_path_);
  } else {
    symbol_path_ = UTF8ToWide(nt_symbol_path);
  }
}
