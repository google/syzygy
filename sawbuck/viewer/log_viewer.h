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
#include "base/lock.h"
#include "sawbuck/sym_util/types.h"
#include "sawbuck/viewer/log_list_view.h"
#include "sawbuck/viewer/stack_trace_list_view.h"

// The log viewer window plays host to a listview, taking care of handling
// its notification requests etc.
class LogViewer : public CSplitterWindowImpl<LogViewer, false> {
 public:
  typedef CSplitterWindowImpl<LogViewer, false> Super;

  static const UINT WM_NEW_MESSAGES = WM_USER + 109;
  BEGIN_MSG_MAP_EX(ViewerWindow)
    MSG_WM_CREATE(OnCreate)
    REFLECT_NOTIFICATIONS()
    CHAIN_MSG_MAP(Super)
  END_MSG_MAP()

  LogViewer();
  ~LogViewer();

  void SetLogView(ILogView* log_view) {
    log_list_view_.SetLogView(log_view);
  }
  void SetSymbolLookupService(ISymbolLookupService* symbol_lookup_service) {
    stack_trace_list_view_.SetSymbolLookupService(symbol_lookup_service);
  }

 private:
  int OnCreate(LPCREATESTRUCT create_struct);

  // The list view that displays the log.
  LogListView log_list_view_;

  // The row # of the item currently displayed in the stack trace.
  int stack_trace_item_row_;

  // The list that displays the stack trace for the currently selected log.
  StackTraceListView stack_trace_list_view_;
};

#endif  // SAWBUCK_VIEWER_LOG_VIEWER_H_
