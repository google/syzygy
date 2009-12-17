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
#ifndef SAWBUCK_VIEWER_LOG_LIST_VIEW_H_
#define SAWBUCK_VIEWER_LOG_LIST_VIEW_H_

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlctrls.h>
#include <atlmisc.h>
#include <string>
#include <vector>
#include "base/lock.h"
#include "base/time.h"
#include "sawbuck/sym_util/types.h"

class ILogViewEvents {
 public:
  virtual void LogViewChanged() = 0;
};

// Provides a view on a log, the view may be filtered or sorted
class ILogView {
 public:
  // Returns the number of rows in this view.
  virtual int GetNumRows() = 0;

  virtual int GetSeverity(int row) = 0;
  virtual DWORD GetProcessId(int row) = 0;
  virtual DWORD GetThreadId(int row) = 0;
  virtual base::Time GetTime(int row) = 0;
  virtual std::string GetFileName(int row) = 0;
  virtual int GetLine(int row) = 0;
  virtual std::string GetMessage(int row) = 0;
  virtual void GetStackTrace(int row, std::vector<void*>* trace) = 0;

  // Register for change notifications.
  virtual void Register(ILogViewEvents* event_sink,
                        int* registration_cookie) = 0;
  virtual void Unregister(int registration_cookie) = 0;
};

// Fwd.
class StackTraceListView;

// Traits specialization for log list view.
typedef CWinTraits<WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS |
    LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA, 0>
        LogListViewTraits;

// List view control subclass that manages the log view.
class LogListView
    : public CWindowImpl<LogListView, CListViewCtrl, LogListViewTraits>,
      public ILogViewEvents {
 public:
  typedef CWindowImpl<LogListView, CListViewCtrl> WindowBase;
  DECLARE_WND_SUPERCLASS(NULL, WindowBase::GetWndClassName())

  enum {
    WM_NOTIFY_LOG_CHANGED = WM_USER + 0x137
  };

  BEGIN_MSG_MAP_EX(LogList)
    MESSAGE_HANDLER(WM_CREATE, OnCreate)
    MSG_WM_DESTROY(OnDestroy)
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_GETDISPINFO, OnGetDispInfo)
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_ITEMCHANGED, OnItemChanged)
    MESSAGE_HANDLER(WM_NOTIFY_LOG_CHANGED, OnNotifyLogChanged)
    DEFAULT_REFLECTION_HANDLER()
  END_MSG_MAP()

  LogListView();

  void SetLogView(ILogView* log_view);
  void SetStackTraceView(StackTraceListView* stack_trace_view);

  virtual void LogViewChanged();

 private:
  // The columns our list view displays.
  enum Columns {
    COL_SEVERITY,
    COL_PROCESS,
    COL_THREAD,
    COL_TIME,
    COL_FILE,
    COL_LINE,
    COL_MESSAGE,

    // Must be last.
    COL_MAX,
  };

  LRESULT OnCreate(UINT msg, WPARAM wparam, LPARAM lparam, BOOL& handled);
  void OnDestroy();
  LRESULT OnNotifyLogChanged(UINT msg,
                             WPARAM wparam,
                             LPARAM lparam,
                             BOOL& handled);

  LRESULT OnGetDispInfo(LPNMHDR notification);
  LRESULT OnItemChanged(LPNMHDR notification);

  // The stack trace view that displays our stack trace.
  StackTraceListView* stack_trace_view_;

  ILogView* log_view_;
  int event_cookie_;

  // Image indexes for severity, stored by severity value.
  std::vector<int> image_indexes_;
  int GetImageIndexForSeverity(int severity);

  Lock lock_;
  bool notification_pending_;  // Under lock_.

  // Temporary storage for strings returned from OnGetDispInfo.
  std::wstring item_text_;
};

#endif  // SAWBUCK_VIEWER_LOG_LIST_VIEW_H_
