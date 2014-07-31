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
#include "sawbuck/viewer/log_viewer.h"

#include <atlbase.h>
#include <atlframe.h>
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/viewer/filtered_log_view.h"
#include "sawbuck/viewer/filter_dialog.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/preferences.h"

LogViewer::LogViewer(CUpdateUIBase* update_ui)
    : log_list_view_(update_ui),
      stack_trace_list_view_(update_ui),
      log_view_(NULL),
      update_ui_(update_ui) {
}

LogViewer::~LogViewer() {
}

void LogViewer::SetLogView(ILogView* log_view) {
  DCHECK(log_view_ == NULL);
  log_view_ = log_view;
  log_list_view_.SetLogView(log_view);
}

int LogViewer::OnCreate(LPCREATESTRUCT create_struct) {
  DCHECK(log_view_ != NULL) << "SetLogView not called before window creation.";

  BOOL bHandled = TRUE;
  Super::OnCreate(WM_CREATE,
                  NULL,
                  reinterpret_cast<LPARAM>(create_struct),
                  bHandled);

  // Create the log list view.
  log_list_view_.Create(m_hWnd);

  // Create the stack trace list view.
  stack_trace_list_view_.Create(m_hWnd);

  log_list_view_.set_stack_trace_view(&stack_trace_list_view_);

  SetDefaultActivePane(SPLIT_PANE_TOP);
  SetSplitterPanes(log_list_view_.m_hWnd, stack_trace_list_view_.m_hWnd);
  SetSplitterExtendedStyle(SPLIT_BOTTOMALIGNED);

  // This is enabled so long as we live.
  update_ui_->UIEnable(ID_LOG_FILTER, true);

  // Read in any previously set filters.
  std::string filter_string;
  Preferences prefs;
  prefs.ReadStringValue(config::kFilterValues, &filter_string, "");
  if (!filter_string.empty()) {
    std::vector<Filter> filters(Filter::DeserializeFilters(filter_string));
    if (!filters.empty()) {
      scoped_ptr<FilteredLogView> new_view(new FilteredLogView(log_view_,
                                                               filters));
      log_list_view_.SetLogView(new_view.get());
      filtered_log_view_.reset(new_view.release());
    }
  }

  SetMsgHandled(FALSE);
  return 1;
}

LRESULT LogViewer::OnCommand(UINT msg,
                             WPARAM wparam,
                             LPARAM lparam,
                             BOOL& handled) {
  HWND window = GetSplitterPane(GetActivePane());
  return ::SendMessage(window, msg, wparam, lparam);
}

void LogViewer::OnLogFilter(UINT code, int id, CWindow window) {
  FilterDialog dialog;

  if (dialog.DoModal(m_hWnd) == IDOK) {
    std::vector<Filter> filters = dialog.get_filters();
    Preferences pref;
    pref.WriteStringValue(config::kFilterValues,
                          Filter::SerializeFilters(filters));

    // TODO(robertshield): If dialog.get_filters() is empty, we should set it
    // back to the non filtered log view.
    scoped_ptr<FilteredLogView> new_view(new FilteredLogView(log_view_,
                                                             filters));
    log_list_view_.SetLogView(new_view.get());
    filtered_log_view_.reset(new_view.release());
  }
}

void LogViewer::OnIncludeColumn(UINT code, int id, CWindow window) {
  // TODO(siggi): write me.
}

void LogViewer::OnExcludeColumn(UINT code, int id, CWindow window) {
  // TODO(siggi): write me.
}
