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
// Log viewer window declaration.
#ifndef SAWBUCK_VIEWER_VIEWER_WINDOW_H_
#define SAWBUCK_VIEWER_VIEWER_WINDOW_H_

#include <atlbase.h>
#include <atlcrack.h>
#include <atlapp.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include <atlframe.h>
#include <atlmisc.h>
#include <atlres.h>
#include <map>
#include <string>
#include <vector>
#include "base/cancelable_callback.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread.h"
#include "base/win/event_trace_controller.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"
#include "sawbuck/log_lib/log_consumer.h"
#include "sawbuck/log_lib/process_info_service.h"
#include "sawbuck/log_lib/symbol_lookup_service.h"
#include "sawbuck/viewer/log_viewer.h"
#include "sawbuck/viewer/provider_configuration.h"
#include "sawbuck/viewer/resource.h"


class ViewerWindow
    : public CFrameWindowImpl<ViewerWindow>,
      public LogEvents,
      public TraceEvents,
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
    COMMAND_ID_HANDLER(ID_FILE_IMPORT, OnImport)
    COMMAND_ID_HANDLER(ID_FILE_EXIT, OnExit)
    COMMAND_ID_HANDLER(ID_APP_ABOUT, OnAbout)
    COMMAND_ID_HANDLER(ID_LOG_CONFIGUREPROVIDERS, OnConfigureProviders)
    COMMAND_ID_HANDLER(ID_LOG_CAPTURE, OnToggleCapture)
    COMMAND_ID_HANDLER(ID_LOG_SYMBOLPATH, OnSymbolPath)
    // Forward other commands to the client window.
    CHAIN_CLIENT_COMMANDS()
    CHAIN_MSG_MAP(CUpdateUI<ViewerWindow>);
    CHAIN_MSG_MAP(SuperFrame);
  END_MSG_MAP()

  BEGIN_UPDATE_UI_MAP(ViewerWindow)
    UPDATE_ELEMENT(ID_FILE_IMPORT, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_LOG_CAPTURE, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_LOG_FILTER, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_AUTOSIZE_COLUMNS, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CUT, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_COPY, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_PASTE, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CLEAR, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_CLEAR_ALL, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_SELECT_ALL, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_FIND, UPDUI_MENUBAR)
    UPDATE_ELEMENT(ID_EDIT_FIND_NEXT, UPDUI_MENUBAR)
    UPDATE_ELEMENT(0, UPDUI_STATUSBAR)
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

  // Turn capturing on or off.
  virtual void SetCapture(bool capture);

  // Consumes the logs in paths.
  void ImportLogFiles(const std::vector<base::FilePath>& paths);

 private:
  LRESULT OnImport(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnExit(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnAbout(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnConfigureProviders(WORD code, LPARAM lparam, HWND wnd,
      BOOL& handled);
  LRESULT OnToggleCapture(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);
  LRESULT OnSymbolPath(WORD code, LPARAM lparam, HWND wnd, BOOL& handled);

  virtual BOOL OnIdle();
  virtual BOOL PreTranslateMessage(MSG* pMsg);
  int OnCreate(LPCREATESTRUCT lpCreateStruct);
  void OnDestroy();

  // Host for compile-time asserts on privates.
  static void CompileAsserts();

  void StopCapturing();
  bool StartCapturing();

 private:
  // Initializes the symbol path.
  void InitSymbolPath();

  // Called on UI thread to dispatch notifications to listeners.
  void NotifyLogViewNewItems();
  void NotifyLogViewCleared();

  // LogEvents implementation.
  void OnLogMessage(const LogEvents::LogMessage& log_message);

  // Invoked on the background thread by the symbol service.
  void OnStatusUpdate(const wchar_t* status);
  // Invoked on the UI thread to update our status.
  void UpdateStatus();

  // TraceEvents implementation.
  void OnTraceEventBegin(const TraceEvents::TraceMessage& trace_message);
  void OnTraceEventEnd(const TraceEvents::TraceMessage& trace_message);
  void OnTraceEventInstant(const TraceEvents::TraceMessage& trace_message);

  // Adds a trace event to the log.
  void AddTraceEventToLog(const char* type,
                          const TraceEvents::TraceMessage& trace_message);

  // Schedule a notification of new items on UI thread.
  // Must be called under list_lock_.
  void ScheduleNewItemsNotification();

  void EnableProviders(const ProviderConfiguration& settings);

  // The currently configured symbol path.
  std::wstring symbol_path_;

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

  base::Lock list_lock_;
  typedef std::vector<LogMessage> LogMessageList;
  LogMessageList log_messages_;  // Under list_lock_.

  typedef base::CancelableCallback<void()> NotifyNewItemsCallback;

  // Keeps the task pending to notify event sinks on the UI thread.
  NotifyNewItemsCallback notify_log_view_new_items_;
  bool notify_log_view_new_items_pending_;  // Under list_lock_.

  // The message loop we're instantiated on, used to signal
  // back to the main thread from workers.
  base::MessageLoop* ui_loop_;

  typedef std::map<int, ILogViewEvents*> EventSinkMap;
  EventSinkMap event_sinks_;
  int next_sink_cookie_;

  // The symbol lookup service we provide to the log list view.
  SymbolLookupService symbol_lookup_service_;
  typedef base::Callback<void(const wchar_t*)> StatusCallback;
  StatusCallback status_callback_;

  base::Lock status_lock_;
  typedef base::CancelableCallback<void()> UpdateStatusCallback;
  UpdateStatusCallback update_status_task_;
  std::wstring status_;  // Under status_lock_.
  bool update_status_task_pending_;  // Under status_lock_;

  // Takes care of sinking KernelProcessEvents for us.
  ProcessInfoService process_info_service_;

  // The list view control that displays log_messages_.
  LogViewer log_viewer_;

  // Controller for the logging session.
  base::win::EtwTraceController log_controller_;

  // Log level settings for the providers we know of.
  ProviderConfiguration settings_;

  // Controller for the kernel logging session.
  base::win::EtwTraceController kernel_controller_;

  // NULL until StartConsuming. Valid until StopConsuming.
  scoped_ptr<LogConsumer> log_consumer_;
  scoped_ptr<KernelLogConsumer> kernel_consumer_;
  base::Thread log_consumer_thread_;
  base::Thread kernel_consumer_thread_;
};

#endif  // SAWBUCK_VIEWER_VIEWER_WINDOW_H_
