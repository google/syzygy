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
#include "sawbuck/viewer/log_list_view.h"

#include <atlframe.h>
#include <wmistr.h>
#include <evntrace.h>
#include "base/string_util.h"
#include "sawbuck/sym_util/symbol_cache.h"
#include "sawbuck/viewer/stack_trace_list_view.h"

namespace {

const wchar_t* kLogViewColumns[] = {
  L"",  // Severity is an icon
  L"Process ID",
  L"Thread ID",
  L"Time",
  L"File",
  L"Line",
  L"Message",
};

}  // namespace

LogListView::LogListView(CUpdateUIBase* update_ui)
    : log_view_(NULL), event_cookie_(0),
      notification_pending_(false), update_ui_(update_ui),
      stack_trace_view_(NULL) {
  COMPILE_ASSERT(arraysize(kLogViewColumns) == COL_MAX,
                 wrong_number_of_column_names);
}

void LogListView::SetLogView(ILogView* log_view) {
  log_view_ = log_view;
}

void LogListView::SetStackTraceView(StackTraceListView* stack_trace_view) {
  stack_trace_view_ = stack_trace_view;
}

LRESULT LogListView::OnCreate(UINT msg,
                              WPARAM wparam,
                              LPARAM lparam,
                              BOOL& handled) {
  // Call through to the original window class first.
  LRESULT ret = DefWindowProc(msg, wparam, lparam);

  CImageList image_list;
  image_list.Create(16, 16, ILC_COLOR24 | ILC_MASK, 4, 0);

  image_indexes_.resize(10);
  image_indexes_[TRACE_LEVEL_FATAL] =
      image_list.AddIcon(::LoadIcon(NULL, MAKEINTRESOURCE(IDI_ERROR)));
  image_indexes_[TRACE_LEVEL_ERROR] =
      image_list.AddIcon(::LoadIcon(NULL, MAKEINTRESOURCE(IDI_ERROR)));
  image_indexes_[TRACE_LEVEL_WARNING] =
      image_list.AddIcon(::LoadIcon(NULL, MAKEINTRESOURCE(IDI_WARNING)));
  image_indexes_[TRACE_LEVEL_INFORMATION] =
      image_list.AddIcon(::LoadIcon(NULL, MAKEINTRESOURCE(IDI_INFORMATION)));
  image_indexes_[TRACE_LEVEL_VERBOSE] =
      image_list.AddIcon(::LoadIcon(NULL, MAKEINTRESOURCE(IDI_QUESTION)));

  SetImageList(image_list, LVSIL_SMALL);

  for (int i = 0; i < COL_MAX; ++i)
    AddColumn(kLogViewColumns[i], i, -1);

  // Tune our extended styles.
  SetExtendedListViewStyle(LVS_EX_HEADERDRAGDROP |
                           LVS_EX_FULLROWSELECT |
                           LVS_EX_INFOTIP |
                           LVS_EX_DOUBLEBUFFER);

  // Pick up the log size if we have one already.
  if (log_view_ != NULL) {
    int num_rows = log_view_->GetNumRows();
    SetItemCountEx(num_rows, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    // We initially want to show the latest items
    EnsureVisible(num_rows - 1, TRUE /* PartialOK */);
  }

  if (log_view_ != NULL)
    log_view_->Register(this, &event_cookie_);

  return ret;
}

void LogListView::OnDestroy() {
  if (log_view_ != NULL)
    log_view_->Unregister(event_cookie_);
}

LRESULT LogListView::OnNotifyLogChanged(UINT msg,
                                        WPARAM wparam,
                                        LPARAM lparam,
                                        BOOL& handled) {
  {
    AutoLock lock(lock_);
    notification_pending_ = false;
  }

  // Check if last item was previously visible...
  BOOL is_last_item_visible = ListView_IsItemVisible(m_hWnd,
                                                     GetItemCount() - 1);
  int num_rows = log_view_->GetNumRows();
  SetItemCountEx(num_rows, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

  // We want to show the latest items if the previously latest one was visible.
  if (is_last_item_visible)
    EnsureVisible(num_rows - 1, TRUE /* PartialOK */);

  return 0;
}

LRESULT LogListView::OnGetDispInfo(LPNMHDR pnmh) {
  NMLVDISPINFO* info = reinterpret_cast<NMLVDISPINFO*>(pnmh);
  int col = info->item.iSubItem;
  size_t row = info->item.iItem;

  switch (col) {
    case COL_SEVERITY:
      item_text_ = L"";
      if (info->item.mask & LVIF_IMAGE)
        info->item.iImage =
            GetImageIndexForSeverity(log_view_->GetSeverity(row));
      break;
    case COL_PROCESS:
      item_text_ = StringPrintf(L"%d", log_view_->GetProcessId(row));
      break;
    case COL_THREAD:
      item_text_ = StringPrintf(L"%d", log_view_->GetThreadId(row));
      break;
    case COL_TIME:
      {
        // TODO(siggi): Find a saner way to format the time.
        FILETIME time = log_view_->GetTime(row).ToFileTime();
        SYSTEMTIME sys_time;
        // Convert to local time.
        ::FileTimeToLocalFileTime(&time, &time);
        ::FileTimeToSystemTime(&time, &sys_time);

        item_text_ = StringPrintf(L"%02d:%02d:%02d-%03d",
                                  sys_time.wHour,
                                  sys_time.wMinute,
                                  sys_time.wSecond,
                                  sys_time.wMilliseconds);
      }
      break;
    case COL_FILE:
      item_text_ = UTF8ToWide(log_view_->GetFileName(row));
      break;
    case COL_LINE:
      item_text_ = StringPrintf(L"%d", log_view_->GetLine(row));
      break;
    case COL_MESSAGE:
      item_text_ = UTF8ToWide(log_view_->GetMessage(row));
      break;
  }

  if (info->item.mask & LVIF_TEXT)
    info->item.pszText = const_cast<LPWSTR>(item_text_.c_str());

  return 0;
}

LRESULT LogListView::OnItemChanged(LPNMHDR pnmh) {
  LPNMLISTVIEW info = reinterpret_cast<LPNMLISTVIEW>(pnmh);
  int row = info->iItem;

  if (stack_trace_view_ != NULL) {
    int item = info->iItem;
    if (info->uNewState & LVIS_SELECTED) {
      std::vector<void*> trace;
      log_view_->GetStackTrace(row, &trace);
      stack_trace_view_->SetStackTrace(log_view_->GetProcessId(row),
                                       log_view_->GetTime(row),
                                       trace.size(),
                                       trace.size() ? &trace[0] : NULL);

    } else {
      // Clear the trace.
      stack_trace_view_->SetStackTrace(0, base::Time::Now(), 0, NULL);
    }
  }

  UpdateCommandStatus(true);

  return 0;
}

int LogListView::GetImageIndexForSeverity(int severity) {
  if (image_indexes_.size() > static_cast<size_t>(severity))
    return image_indexes_[severity];
  return -1;
}

void LogListView::OnCopyCommand(UINT code, int id, CWindow window) {
  // TODO(siggi): implement copy.
  ::MessageBeep(MB_OK);
}

void LogListView::OnSetFocus(CWindow window) {
  UpdateCommandStatus(true);

  // Give the list view a chance at the message.
  SetMsgHandled(FALSE);
}

void LogListView::OnKillFocus(CWindow window) {
  UpdateCommandStatus(false);

  // Give the list view a chance at the message.
  SetMsgHandled(FALSE);
}

void LogListView::LogViewChanged() {
  if (IsWindow()) {
    AutoLock lock(lock_);

    if (!notification_pending_) {
      notification_pending_ = true;
      ::PostMessage(m_hWnd, WM_NOTIFY_LOG_CHANGED, 0, 0);
    }
  }
}

void LogListView::UpdateCommandStatus(bool has_focus) {
  bool has_selection = GetSelectedCount() != 0;

  update_ui_->UIEnable(ID_EDIT_COPY, has_focus && has_selection);
}
