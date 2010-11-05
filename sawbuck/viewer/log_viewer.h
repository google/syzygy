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
#ifndef SAWBUCK_VIEWER_LOG_VIEWER_H_
#define SAWBUCK_VIEWER_LOG_VIEWER_H_

#include <atlbase.h>
#include <atlcrack.h>
#include <atlapp.h>
#include <atlctrls.h>
#include <atlsplit.h>
#include <atlmisc.h>
#include "base/scoped_ptr.h"
#include "sawbuck/viewer/log_list_view.h"
#include "sawbuck/viewer/resource.h"
#include "sawbuck/viewer/stack_trace_list_view.h"

// Forward decl.
namespace WTL {
class CUpdateUIBase;
};
class FilteredLogView;
class IProcessInfoService;

// The log viewer window plays host to a listview, taking care of handling
// its notification requests etc.
class LogViewer : public CSplitterWindowImpl<LogViewer, false> {
 public:
  typedef CSplitterWindowImpl<LogViewer, false> Super;

  static const UINT WM_NEW_MESSAGES = WM_USER + 109;
  BEGIN_MSG_MAP_EX(ViewerWindow)
    MSG_WM_CREATE(OnCreate)
    REFLECT_NOTIFICATIONS()
    COMMAND_ID_HANDLER_EX(ID_LOG_FILTER, OnLogFilter)
    COMMAND_ID_HANDLER_EX(ID_INCLUDE_COLUMN, OnIncludeColumn)
    COMMAND_ID_HANDLER_EX(ID_EXCLUDE_COLUMN, OnExcludeColumn)
    MESSAGE_HANDLER(WM_COMMAND, OnCommand)
    CHAIN_MSG_MAP(Super)
  END_MSG_MAP()

  explicit LogViewer(CUpdateUIBase* update_ui);
  ~LogViewer();

  // This must be called before the log window viewer is created.
  void SetLogView(ILogView* log_view);

  void SetSymbolLookupService(ISymbolLookupService* symbol_lookup_service) {
    stack_trace_list_view_.SetSymbolLookupService(symbol_lookup_service);
  }
  void SetProcessInfoService(IProcessInfoService* process_info_service) {
    log_list_view_.set_process_info_service(process_info_service);
  }

 private:
  int OnCreate(LPCREATESTRUCT create_struct);
  LRESULT OnCommand(UINT msg, WPARAM wparam, LPARAM lparam, BOOL& handled);
  void OnLogFilter(UINT code, int id, CWindow window);
  void OnIncludeColumn(UINT code, int id, CWindow window);
  void OnExcludeColumn(UINT code, int id, CWindow window);

  // Non-null iff filtering is enabled.
  scoped_ptr<FilteredLogView> filtered_log_view_;

  // The original log view we're handed.
  ILogView* log_view_;

  // The list view that displays the log.
  LogListView log_list_view_;

  // The row # of the item currently displayed in the stack trace.
  int stack_trace_item_row_;

  // The list that displays the stack trace for the currently selected log.
  StackTraceListView stack_trace_list_view_;

  // Used to update our UI.
  CUpdateUIBase* update_ui_;
};

#endif  // SAWBUCK_VIEWER_LOG_VIEWER_H_
