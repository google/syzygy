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

// A regular expression that matches "[<stuff>:<file>(<line>)].message"
// and extracts the file/line/message parts.
const pcrecpp::RE kFileRe("\\[[^\\]]*\\:([^:]+)\\((\\d+)\\)\\].(.*\\w).*",
                          PCRE_NEWLINE_ANYCRLF | PCRE_DOTALL | PCRE_UTF8);

const wchar_t kSessionName[] = L"Sawbuck Log Session";

bool Is64BitSystem() {
  if (sizeof(void*) == 8)
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

ViewerWindow::ViewerWindow() : log_message_size_dirty_(false),
  symbol_lookup_worker_("Symbol Lookup Worker"), next_sink_cookie_(1),
  log_viewer_(this) {

  symbol_lookup_worker_.Start();

  ReadProviderSettings(&settings_);
}

ViewerWindow::~ViewerWindow() {
  // Last resort..
  StopCapturing();

  symbol_lookup_worker_.Stop();
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
  if (log_consumer_thread_ != NULL) {
    DWORD ret = ::WaitForSingleObject(log_consumer_thread_, INFINITE);
    ATLASSERT(ret == WAIT_OBJECT_0);
    log_consumer_thread_.Close();
  }
  log_consumer_.reset();

  if (kernel_consumer_thread_ != NULL) {
    DWORD ret = ::WaitForSingleObject(kernel_consumer_thread_, INFINITE);
    ATLASSERT(ret == WAIT_OBJECT_0);
    kernel_consumer_thread_.Close();
  }
  kernel_consumer_.reset();
}

bool ViewerWindow::StartCapturing() {
  ATLASSERT(NULL == log_controller_.session());
  ATLASSERT(NULL == kernel_controller_.session());
  ATLASSERT(NULL == log_consumer_.get());
  ATLASSERT(NULL == kernel_consumer_.get());

  // Open a session for our log message capturing.
  HRESULT hr = log_controller_.StartRealtimeSession(kSessionName, 1024);
  if (FAILED(hr))
    return false;

  // And open a consumer on it.
  log_consumer_.reset(new LogConsumer());
  log_consumer_->set_event_sink(this);
  hr = log_consumer_->OpenRealtimeSession(kSessionName);
  if (FAILED(hr))
    return false;

  // Consume it in a new thread.
  log_consumer_thread_.Attach(::CreateThread(
      NULL, 0, LogConsumer::ThreadProc, log_consumer_.get(), 0, NULL));

  // Start the kernel logger session.
  EtwTraceProperties prop;
  EVENT_TRACE_PROPERTIES* p = prop.get();
  p->Wnode.Guid = SystemTraceControlGuid;
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->MaximumFileSize = 100;  // 100 M file size.
  // Get image load events.
  p->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD;
  p->FlushTimer = 1;  // flush every second.
  p->BufferSize = 16;  // 16 K buffers.
  hr = kernel_controller_.Start(KERNEL_LOGGER_NAME, &prop);
  if (FAILED(hr))
    return false;

  // And open a consumer on it.
  kernel_consumer_.reset(new KernelLogConsumer());
  ATLASSERT(NULL != kernel_consumer_.get());
  kernel_consumer_->set_module_event_sink(this);
  kernel_consumer_->set_is_64_bit_log(Is64BitSystem());
  hr = kernel_consumer_->OpenRealtimeSession(KERNEL_LOGGER_NAME);
  if (FAILED(hr))
    return false;

  // Consume it in a new thread.
  kernel_consumer_thread_.Attach(::CreateThread(
      NULL, 0, KernelLogConsumer::ThreadProc,
      kernel_consumer_.get(), 0, NULL));
  if (kernel_consumer_thread_ == NULL)
    hr = AtlHresultFromLastError();

  if (SUCCEEDED(hr))
    EnableProviders(settings_);

  return SUCCEEDED(hr);
}

void ViewerWindow::EnableProviders(
    const std::vector<ProviderSettings>& settings) {
  for (size_t i = 0; i < settings.size(); ++i) {
    log_controller_.EnableProvider(
        settings[i].provider_guid, settings[i].log_level);
  }
}

void ViewerWindow::OnLogMessage(UCHAR level,
                                DWORD process_id,
                                DWORD thread_id,
                                LARGE_INTEGER time_stamp,
                                size_t num_traces,
                                void** trace,
                                size_t length,
                                const char* message) {
  AutoLock lock(list_lock_);

  // Trim trailing zeros and WS off the message.
  while (length && message[length] == '\0')
    --length;

  log_messages_.push_back(LogMessage());
  LogMessage& msg = log_messages_.back();
  msg.level = level;
  msg.process_id = process_id;
  msg.thread_id = thread_id;
  msg.time_stamp =
      base::Time::FromFileTime(reinterpret_cast<FILETIME&>(time_stamp));

  // Use regular expression matching to extract the
  // file/line/message from the log string, which is of
  // format "[<stuff>:<file>(<line>)] <message><ws>".
  if (!kFileRe.FullMatch(pcrecpp::StringPiece(message, length),
                         &msg.file, &msg.line, &msg.message)) {
    // As fallback, just slurp the entire string.
    msg.message.assign(message, length);
  }

  for (size_t i = 0; i < num_traces; ++i)
    msg.trace.push_back(trace[i]);

  EventSinkMap::iterator it(event_sinks_.begin());
  for (; it != event_sinks_.end(); ++it) {
    it->second->LogViewChanged();
  }
}

void ViewerWindow::OnModuleIsLoaded(DWORD process_id,
                                    const base::Time& time,
                                    const ModuleInformation& module_info) {
  return OnModuleLoad(process_id, time, module_info);
}
void ViewerWindow::OnModuleUnload(DWORD process_id,
                                  const base::Time& time,
                                  const ModuleInformation& module_info) {
  AutoLock lock(symbol_lock_);
  module_cache_.ModuleUnloaded(process_id, time, module_info);
}

void ViewerWindow::OnModuleLoad(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info) {
  AutoLock lock(symbol_lock_);

  std::wstring file_path(module_info.image_file_name);
  // Map device paths to drive paths.
  DWORD drives = ::GetLogicalDrives();
  char drive = 'A';
  for (; drives != 0; drives >>= 1, ++drive) {
    if (drives & 1) {
      wchar_t device_path[1024] = {};
      wchar_t device[] = { drive, L':', L'\0' };
      if (::QueryDosDevice(device, device_path, arraysize(device_path)) &&
          file_path.find(device_path) == 0) {
        std::wstring new_path = device;
        new_path += file_path.substr(wcslen(device_path));
        file_path = new_path;
      }
    }
  }

  ModuleInformation& info = const_cast<ModuleInformation&>(module_info);

  info.image_file_name = file_path;
  module_cache_.ModuleLoaded(process_id, time, module_info);
}

LRESULT ViewerWindow::OnConfigureProviders(WORD code,
                                           LPARAM lparam,
                                           HWND wnd,
                                           BOOL& handled) {
  // Make a copy of our settings.
  std::vector<ProviderSettings> settings(settings_);
  ProviderDialog dialog(settings.size(),
                        settings.size() ? &settings[0] : NULL);
  if (dialog.DoModal(m_hWnd) == IDOK) {
    settings_ = settings;
    EnableProviders(settings_);
  }

  return 0;
}

LRESULT ViewerWindow::OnToggleCapture(WORD code,
                                      LPARAM lparam,
                                      HWND wnd,
                                      BOOL& handled) {
  bool capturing = log_controller_.session() != NULL;
  ATLASSERT(capturing ==
      ((UIGetState(ID_LOG_CAPTURE) & UPDUI_CHECKED) == UPDUI_CHECKED));

  if (capturing) {
    StopCapturing();
    capturing = false;
  } else {
    if (StartCapturing()) {
      capturing = true;
    } else {
      StopCapturing();
    }
  }

  UISetCheck(ID_LOG_CAPTURE, capturing);

  return 0;
}

BOOL ViewerWindow::OnIdle() {
  UIUpdateMenuBar();
  UIUpdateToolBar();

  return TRUE;
}

BOOL ViewerWindow::PreTranslateMessage(MSG* msg) {
  return SuperFrame::PreTranslateMessage(msg);
}

int ViewerWindow::OnCreate(LPCREATESTRUCT lpCreateStruct) {
  // TODO(siggi): Make the toolbar useful.
  // CreateSimpleToolBar();
  // Edit menu is disabled by default.
  UIEnable(ID_EDIT_CUT, false);
  UIEnable(ID_EDIT_COPY, false);
  UIEnable(ID_EDIT_PASTE, false);
  UIEnable(ID_EDIT_CLEAR, false);
  UIEnable(ID_EDIT_SELECT_ALL, false);

  CreateSimpleStatusBar();
  SetWindowText(L"Sawbuck Log Viewer");

  log_viewer_.SetLogView(this);
  log_viewer_.SetSymbolLookupService(this);

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
    if (err == ERROR_SUCCESS && size == sizeof(placement))
      SetWindowPlacement(&placement);
  }

  UpdateLayout();
  UIAddMenuBar(m_hWnd);

  CMessageLoop* loop = g_sawbuck_app_module.GetMessageLoop();
  ATLASSERT(loop != NULL);
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
  AutoLock lock(list_lock_);

  int cookie = next_sink_cookie_++;

  event_sinks_.insert(std::make_pair(cookie, event_sink));
  *registration_cookie = cookie;
}

void ViewerWindow::Unregister(int registration_cookie) {
  AutoLock lock(list_lock_);

  event_sinks_.erase(registration_cookie);
}

bool ViewerWindow::ResolveAddress(sym_util::ProcessId pid,
                                  const base::Time& time,
                                  sym_util::Address address,
                                  sym_util::Symbol* symbol) {
  AutoLock lock(symbol_lock_);

  using sym_util::ModuleCache;
  using sym_util::SymbolCache;

  ModuleCache::ModuleLoadStateId id = module_cache_.GetStateId(pid, time);

  SymbolCacheMap::iterator it = symbol_caches_.find(id);
  if (it == symbol_caches_.end()) {
    if (symbol_caches_.size() == kMaxCacheSize) {
      // Evict the least recently used element.
      ModuleCache::ModuleLoadStateId to_evict = lru_module_id_.front();
      lru_module_id_.erase(lru_module_id_.begin());
      symbol_caches_.erase(to_evict);
    }

    std::pair<SymbolCacheMap::iterator, bool> inserted =
        symbol_caches_.insert(std::make_pair(id, SymbolCache()));

    DCHECK_EQ(inserted.second, true);
    SymbolCache& cache = inserted.first->second;

    std::vector<ModuleInformation> modules;
    module_cache_.GetProcessModuleState(pid, time, &modules);
    cache.Initialize(modules.size(), modules.size() ? &modules[0] : NULL);

    it = inserted.first;
  } else {
    // Manage the LRU by removing our ID.
    lru_module_id_.erase(
        std::find(lru_module_id_.begin(), lru_module_id_.end(), id));
  }

  // Push our id to the back of the lru list.
  lru_module_id_.push_back(id);

  DCHECK(it != symbol_caches_.end());
  SymbolCache& cache = it->second;

  return cache.GetSymbolForAddress(address, symbol);
}

void ViewerWindow::ReadProviderSettings(
    std::vector<ProviderSettings>* settings) {
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

  // TODO(siggi): read the settings from registry.
  ProviderNamesMap::const_iterator it(provider_names.begin());
  for (; it != provider_names.end(); ++it) {
    ProviderSettings setting;
    setting.log_level = TRACE_LEVEL_INFORMATION;
    setting.provider_guid = it->first;
    setting.provider_name = it->second;

    settings->push_back(setting);
  }
}

void ViewerWindow::WriteProviderSettings(
    const std::vector<ProviderSettings>& settings) {

}
