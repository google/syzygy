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
// Log viewer window declaration.
#ifndef SAWBUCK_VIEWER_VIEWER_WINDOW_H_
#define SAWBUCK_VIEWER_VIEWER_WINDOW_H_

#include <atlbase.h>
#include <atlcrack.h>
#include <atlapp.h>
#include <atlctrls.h>
#include <atlframe.h>
#include <atlmisc.h>
#include <atlres.h>
#include <atlstr.h>
#include <map>
#include <string>
#include <vector>
#include "base/event_trace_controller_win.h"
#include "base/scoped_ptr.h"
#include "base/lock.h"
#include "base/thread.h"
#include "sawbuck/sym_util/module_cache.h"
#include "sawbuck/sym_util/symbol_cache.h"
#include "sawbuck/viewer/log_viewer.h"
#include "sawbuck/viewer/resource.h"
#include "sawbuck/viewer/kernel_log_consumer.h"
#include "sawbuck/viewer/log_consumer.h"
#include "sawbuck/viewer/symbol_lookup_service.h"


// Log level settings for a provider.
struct ProviderSettings {
  GUID provider_guid;
  std::wstring provider_name;
  UCHAR log_level;
};

class ViewerWindow
    : public CFrameWindowImpl<ViewerWindow>,
      public LogEvents,
      public ILogView,
      public CIdleHandler,
      public CMessageFilter,
      public CUpdateUI<ViewerWindow> {
 public:
  typedef CFrameWindowImpl<ViewerWindow> SuperFrame;

  DECLARE_FRAME_WND_CLASS(NULL, IDR_MAIN_FRAME);
  BEGIN_MSG_MAP_EX(ViewerWindow)
    MSG_WM_CREATE(OnCreate)
    MSG_WM_DESTROY(OnDestroy)
    COMMAND_ID_HANDLER(ID_FILE_EXIT, OnExit)
    COMMAND_ID_HANDLER(ID_APP_ABOUT, OnAbout)
    COMMAND_ID_HANDLER(ID_LOG_CONFIGUREPROVIDERS, OnConfigureProviders)
    COMMAND_ID_HANDLER(ID_LOG_CAPTURE, OnToggleCapture)
    // Forward other commands to the client window.
    CHAIN_CLIENT_COMMANDS()
    CHAIN_MSG_MAP(CUpdateUI<ViewerWindow>);
    CHAIN_MSG_MAP(SuperFrame);
  END_MSG_MAP()

  BEGIN_UPDATE_UI_MAP(ViewerWindow)
    UPDATE_ELEMENT(ID_LOG_CAPTURE, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_LOG_FILTER, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CUT, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_COPY, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_PASTE, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CLEAR, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CLEAR_ALL, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_SELECT_ALL, UPDUI_MENUBAR)
  END_UPDATE_UI_MAP()

  ViewerWindow();
  ~ViewerWindow();

  // ILogView implementation
  virtual int GetNumRows();
  virtual void ClearAll();
  virtual int GetSeverity(int row);
  virtual DWORD GetProcessId(int row);
  virtual DWORD GetThreadId(int row);
  virtual base::Time GetTime(int row);
  virtual std::string GetFileName(int row);
  virtual int GetLine(int row);
  virtual std::string GetMessage(int row);
  virtual void GetStackTrace(int row, std::vector<void*>* stack_trace);

  virtual void Register(ILogViewEvents* event_sink,
                        int* registration_cookie);
  virtual void Unregister(int registration_cookie);

 private:
  LRESULT OnExit(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnAbout(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnConfigureProviders(WORD code, LPARAM lparam, HWND wnd,
      BOOL& handled);
  LRESULT OnToggleCapture(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);

  virtual BOOL OnIdle();
  virtual BOOL PreTranslateMessage(MSG* pMsg);
  int OnCreate(LPCREATESTRUCT lpCreateStruct);
  void OnDestroy();

  // Host for compile-time asserts on privates.
  static void CompileAsserts();

  void StopCapturing();
  bool StartCapturing();

 private:
  // Called on UI thread to dispatch notifications to listeners.
  void NotifyLogViewNewItems();
  void NotifyLogViewCleared();

  void OnLogMessage(UCHAR level,
                    DWORD process_id,
                    DWORD thread_id,
                    LARGE_INTEGER time_stamp,
                    size_t num_traces,
                    void** trace,
                    size_t length,
                    const char* message);

  void EnableProviders(const std::vector<ProviderSettings>& settings);
  void ReadProviderSettings(std::vector<ProviderSettings>* settings);
  void WriteProviderSettings(const std::vector<ProviderSettings>& settings);

  struct LogMessage {
    LogMessage() : level(0), process_id(0), thread_id(0), line(0) {
    }

    UCHAR level;
    DWORD process_id;
    DWORD thread_id;
    base::Time time_stamp;
    std::string file;
    int line;
    std::string message;
    std::vector<void*> trace;
  };

  // We dedicate a thread to the symbol lookup work.
  base::Thread symbol_lookup_worker_;

  Lock list_lock_;
  typedef std::vector<LogMessage> LogMessageList;
  LogMessageList log_messages_;  // Under list_lock_.
  // True iff there is a pending task to notify event sinks on the UI thread.
  bool log_messages_dirty_;  // Under list_lock_.

  // The message loop we're instantiated on, used to signal
  // back to the main thread from workers.
  MessageLoop* ui_loop_;

  typedef std::map<int, ILogViewEvents*> EventSinkMap;
  EventSinkMap event_sinks_;
  int next_sink_cookie_;

  SymbolLookupService symbol_lookup_service_;

  // The list view control that displays log_messages_.
  LogViewer log_viewer_;

  // Controller for the logging session.
  EtwTraceController log_controller_;

  // Log level settings for the providers we know of.
  std::vector<ProviderSettings> settings_;

  // Controller for the kernel logging session.
  EtwTraceController kernel_controller_;

  // NULL until StartConsuming. Valid until StopConsuming.
  scoped_ptr<LogConsumer> log_consumer_;
  scoped_ptr<KernelLogConsumer> kernel_consumer_;
  CHandle log_consumer_thread_;
  CHandle kernel_consumer_thread_;
};

#endif  // SAWBUCK_VIEWER_VIEWER_WINDOW_H_
