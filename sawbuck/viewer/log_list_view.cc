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

#include <atlalloc.h>
#include <atlframe.h>
#include <wmistr.h>
#include <evntrace.h>
#include "base/i18n/time_formatting.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/log_lib/process_info_service.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/resource.h"
#include "sawbuck/viewer/stack_trace_list_view.h"

namespace {

const wchar_t* GetSeverityText(UCHAR severity) {
  switch (severity)  {
    case TRACE_LEVEL_NONE:
      return L"NONE";
    case TRACE_LEVEL_FATAL:
      return L"FATAL";
    case TRACE_LEVEL_ERROR:
      return L"ERROR";
    case TRACE_LEVEL_WARNING:
      return L"WARNING";
    case TRACE_LEVEL_INFORMATION:
      return L"INFORMATION";
    case TRACE_LEVEL_VERBOSE:
      return L"VERBOSE";
    case TRACE_LEVEL_RESERVED6:
      return L"RESERVED6";
    case TRACE_LEVEL_RESERVED7:
      return L"RESERVED7";
    case TRACE_LEVEL_RESERVED8:
      return L"RESERVED8";
    case TRACE_LEVEL_RESERVED9:
      return L"RESERVED9";
  }

  return L"UNKNOWN";
}

// Returns true iff state indicates a selected listview item.
bool IsSelected(UINT state) {
  return (state & LVIS_SELECTED) == LVIS_SELECTED;
}

const int kNoItem = -1;

}  // namespace

const LogListView::ColumnInfo LogListView::kColumns[] = {
  { 24, L"" },  // Severity is an icon
  { 42, L"Process ID" },
  { 42, L"Thread ID" },
  { 80, L"Time" },
  { 180, L"File" },
  { 30, L"Line" },
  { 640, L"Message", }
};

const wchar_t* LogListView::kConfigKeyName =
    config::kSettingsKey;
const wchar_t* LogListView::kColumnOrderValueName =
    config::kLogViewColumnOrder;
const wchar_t* LogListView::kColumnWidthValueName =
    config::kLogViewColumnWidths;


LogListView::LogListView(CUpdateUIBase* update_ui)
    : log_view_(NULL), event_cookie_(0),
      update_ui_(update_ui), stack_trace_view_(NULL),
      process_info_service_(NULL) {
  ui_loop_ = MessageLoop::current();

  context_menu_bar_.LoadMenu(IDR_LIST_VIEW_CONTEXT_MENU);
  context_menu_ = context_menu_bar_.GetSubMenu(0);

  COMPILE_ASSERT(arraysize(kColumns) == COL_MAX,
                 wrong_number_of_column_info);
}

void LogListView::SetLogView(ILogView* log_view) {
  if (log_view_ == log_view)
    return;

  // Unregister from old log view.
  if (log_view_ != NULL) {
    log_view_->Unregister(event_cookie_);
    event_cookie_ = 0;
  }

  // Store the new one.
  log_view_ = log_view;

  // Adjust our size if we've been created already.
  if (IsWindow()) {
    int num_rows = log_view_->GetNumRows();
    SetItemCountEx(num_rows, 0);  // Invalidate the whole list.
    // We initially want to show the latest items
    EnsureVisible(num_rows - 1, TRUE /* PartialOK */);
  }

  // Register for event notifications.
  if (log_view_ != NULL)
    log_view_->Register(this, &event_cookie_);
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
  AddColumns();

  // Tune our extended styles.
  SetExtendedListViewStyle(LVS_EX_HEADERDRAGDROP |
                           LVS_EX_FULLROWSELECT |
                           LVS_EX_INFOTIP |
                           LVS_EX_DOUBLEBUFFER);

  int num_rows = log_view_->GetNumRows();
  SetItemCountEx(num_rows, 0);
  // We initially want to show the latest items
  EnsureVisible(num_rows - 1, TRUE /* PartialOK */);

  return ret;
}

void LogListView::OnDestroy() {
  if (log_view_ != NULL) {
    log_view_->Unregister(event_cookie_);
  }
  SaveColumns();
}

LRESULT LogListView::OnGetDispInfo(NMHDR* pnmh) {
  NMLVDISPINFO* info = reinterpret_cast<NMLVDISPINFO*>(pnmh);
  int col = info->item.iSubItem;
  size_t row = info->item.iItem;

  switch (col) {
    case COL_SEVERITY:
      item_text_ = L"";
      if (info->item.mask & LVIF_IMAGE)
        info->item.iImage =
            GetImageIndexForSeverity(log_view_->GetSeverity(row));

      item_text_ = GetSeverityText(log_view_->GetSeverity(row));
      break;
    case COL_PROCESS:
      item_text_ = StringPrintf(L"%d", log_view_->GetProcessId(row));
      break;
    case COL_THREAD:
      item_text_ = StringPrintf(L"%d", log_view_->GetThreadId(row));
      break;
    case COL_TIME:
      {
        if (!base_time_.is_null()) {
          base::Time row_time = log_view_->GetTime(row);
          base::TimeDelta time_delta = row_time - base_time_;
          bool is_negative = false;

          if (time_delta.ToInternalValue() < 0) {
            is_negative = true;
            time_delta = base_time_ - row_time;
          }

          int64 hours = time_delta.InHours();
          int64 minutes = time_delta.InMinutes() % 60;
          int64 seconds = time_delta.InSeconds() % 60;
          int64 milliseconds = time_delta.InMilliseconds() % 1000;

          if (is_negative) {
            item_text_ = StringPrintf(L"-%02lld:%02lld:%02lld-%03lld",
                                      hours, minutes, seconds, milliseconds);
          } else {
            item_text_ = StringPrintf(L"%02lld:%02lld:%02lld-%03lld",
                                      hours, minutes, seconds, milliseconds);
          }
        } else {
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

  TrimWhitespace(item_text_, TRIM_TRAILING, &item_text_);

  if (info->item.mask & LVIF_TEXT)
    info->item.pszText = const_cast<LPWSTR>(item_text_.c_str());

  return 0;
}

LRESULT LogListView::OnItemChanged(NMHDR* pnmh) {
  NMLISTVIEW* info = reinterpret_cast<NMLISTVIEW*>(pnmh);

  int row = info->iItem;

  if (stack_trace_view_ != NULL) {
    if (IsSelected(info->uNewState) && !IsSelected(info->uOldState)) {
      // Set the stack trace for a single row selection only.
      if (row != kNoItem) {
        std::vector<void*> trace;
        log_view_->GetStackTrace(row, &trace);

        DCHECK(stack_trace_view_ != NULL);
        stack_trace_view_->SetStackTrace(
            log_view_->GetProcessId(row),
            log_view_->GetTime(row),
            trace.size(),
            trace.size() ? &trace[0] : NULL);
      }
    } else if (!IsSelected(info->uNewState) && IsSelected(info->uOldState)) {
      // Clear the trace.
      DCHECK(stack_trace_view_ != NULL);
      stack_trace_view_->SetStackTrace(0, base::Time::Now(), 0, NULL);
    }
  }

  UpdateCommandStatus(true);

  return 0;
}

LRESULT LogListView::OnGetInfoTip(NMHDR* pnmh) {
  NMLVGETINFOTIP* info_tip = reinterpret_cast<NMLVGETINFOTIP*>(pnmh);
  size_t row = info_tip->iItem;

  if (process_info_service_ != NULL) {
    DWORD pid = log_view_->GetProcessId(row);
    base::Time time = log_view_->GetTime(row);

    IProcessInfoService::ProcessInfo info = {};
    if (process_info_service_->GetProcessInfo(pid, time, &info)) {
      std::wstringstream text;

      text << L"Process: " << info.command_line_ << std::endl;
      if (info.started_ != base::Time()) {
        text << L"Started: "
            << base::TimeFormatShortDateAndTime(info.started_) << std::endl;
      }
      if (info.ended_ != base::Time()) {
        text << L"Ended: "
            << base::TimeFormatShortDateAndTime(info.ended_) << std::endl
            << L"Exit code: " << info.exit_code_ << std::endl;
      }

      wcscpy_s(info_tip->pszText, info_tip->cchTextMax, text.str().c_str());
    }
  }

  return 0;
}

int LogListView::GetImageIndexForSeverity(int severity) {
  if (image_indexes_.size() > static_cast<size_t>(severity))
    return image_indexes_[severity];
  return -1;
}

void LogListView::OnCopyCommand(UINT code, int id, CWindow window) {
  std::wstringstream selection;

  int item = GetNextItem(kNoItem, LVNI_SELECTED);
  for (; item != kNoItem; item = GetNextItem(item, LVNI_SELECTED)) {
    NMLVDISPINFO info = {};

    info.hdr.hwndFrom = m_hWnd;
    info.item.iItem = item;
    info.item.mask = LVIF_TEXT;

    for (int col = COL_SEVERITY; col < COL_MAX; ++col) {
      info.item.iSubItem = col;

      OnGetDispInfo(&info.hdr);

      // Tab separate the columns.
      if (col != COL_SEVERITY)
        selection << L'\t';
      selection << info.item.pszText;
    }

    // Clipboard has CRLF separated lines.
    selection << L"\r\n";
  }

  // Copy the sstring to a global pointer for the clipboard.
  CHeapPtr<wchar_t, CGlobalAllocator> data;

  if (!data.Allocate(selection.str().length() + 1)) {
    LOG(ERROR) << "Unable to allocate clipboard data";
    return;
  }

  // Copy the string and the terminating zero.
  memcpy(data.m_pData,
         &selection.str()[0],
         (selection.str().length() + 1) * sizeof(wchar_t));

  if (::OpenClipboard(m_hWnd)) {
    ::EmptyClipboard();

    if (::SetClipboardData(CF_UNICODETEXT, data.m_pData)) {
      // The clipboard has taken ownership now.
      data.Detach();
    } else {
      LOG(ERROR) << "Unable to set clipboard data, error  "
          << ::GetLastError();
    }

    ::CloseClipboard();
  } else  {
    LOG(ERROR) << "Unable to open clipboard, error " << ::GetLastError();
  }
}

void LogListView::OnSelectAll(UINT code, int id, CWindow window) {
  // Select all items.
  SetItemState(kNoItem, LVIS_SELECTED, LVIS_SELECTED);
}

void LogListView::OnClearAll(UINT code, int id, CWindow window) {
  // Clear all items from the log view and then wait for change notifications.
  log_view_->ClearAll();
  // And clear the stack trace as well.
  if (stack_trace_view_)
    stack_trace_view_->SetStackTrace(0, base::Time::Now(), 0, NULL);
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

void LogListView::OnContextMenu(CWindow wnd, CPoint point) {
  int row = -1;
  if (point.x == -1 && point.y == -1) {
    // On shift-F10, the point is (-1, -1)
    row = GetNextItem(-1, LVIS_FOCUSED);
    if (row != -1) {
      // Set the point to the middle of the label of the found item.
      CRect rc;
      GetItemRect(row, &rc, LVIR_LABEL);
      point.x = (rc.left + rc.right) / 2;
      point.y = (rc.bottom + rc.top) / 2;
    } else {
      // If no found item, backoff to the top-left of our client area.
      point.x = point.y = 0;
    }
    ClientToScreen(&point);
  } else {
    // Hit test to make sure that we clicked on an item.
    CPoint client_point(point);
    ScreenToClient(&client_point);
    row = HitTest(client_point, NULL);
  }

  if (row == -1) {
    context_menu_.EnableMenuItem(ID_SET_TIME_ZERO, MF_BYCOMMAND | MF_GRAYED);
  } else {
    context_menu_.EnableMenuItem(ID_SET_TIME_ZERO, MF_BYCOMMAND | MF_ENABLED);
  }

  if (base_time_.is_null()) {
    context_menu_.EnableMenuItem(ID_RESET_BASE_TIME, MF_BYCOMMAND | MF_GRAYED);
  } else {
    context_menu_.EnableMenuItem(ID_RESET_BASE_TIME, MF_BYCOMMAND | MF_ENABLED);
  }

  const UINT kMenuFlags = TPM_LEFTALIGN | TPM_VCENTERALIGN | TPM_RIGHTBUTTON |
                          TPM_HORPOSANIMATION | TPM_VERPOSANIMATION;
  context_menu_.TrackPopupMenu(0, point.x, point.y, wnd);
}

void LogListView::OnFind(UINT code, int id, CWindow window) {
  FindDialog find(find_params_);
  if (find.DoModal(m_hWnd) == IDOK) {
    find_params_ = find.find_params();
    FindNext();
  }
}

void LogListView::OnFindNext(UINT code, int id, CWindow window) {
  if (!find_params_.expression_.empty())
    FindNext();
}

void LogListView::OnAutoSizeColumns(UINT code, int id, CWindow window) {
  int columns = GetHeader().GetItemCount();
  // Skip resizing the severity column.
  for (int i = 1; i < columns; ++i)
    SetColumnWidth(i, LVSCW_AUTOSIZE);
}

void LogListView::FindNext() {
  pcrecpp::RE_Options options = PCRE_UTF8;
  options.set_caseless(!find_params_.match_case_);
  pcrecpp::RE expression(find_params_.expression_, options);

  int start = GetNextItem(-1, LVIS_FOCUSED);
  int num_rows = log_view_->GetNumRows();
  bool down = find_params_.direction_down_;
  int i = down ? start + 1 : start - 1;
  if (i < 0)
    i = 0;  // in case start == -1.

  for (; down ? i < num_rows : i >= 0; down ? ++i : --i) {
    std::string message(log_view_->GetMessage(i));
    if (expression.PartialMatch(message))
      break;
  }

  if (i >= 0 && i < num_rows) {
    // Clear the existing selection.
    if (start >= 0)
      SetItemState(start, 0, LVIS_SELECTED | LVIS_FOCUSED);

    // Select and focus the new item.
    SetItemState(i, LVIS_SELECTED | LVIS_FOCUSED,
                 LVIS_SELECTED | LVIS_FOCUSED);
    EnsureVisible(i, false);
  } else {
    MessageBox(L"The specified text was not found.");
  }
}

void LogListView::OnSetBaseTime(UINT code, int id, CWindow window) {
  // Get the focused item.
  int row = GetNextItem(-1, LVIS_FOCUSED);
  if (row == -1) {
    NOTREACHED() << "No focused element";
    return;
  }

  // Get the corresponding time.
  base_time_ = log_view_->GetTime(row);

  // Refresh the list.
  RedrawItems(0, GetItemCount());
}

void LogListView::OnResetBaseTime(UINT code, int id, CWindow window) {
  base_time_ = base::Time();

  // Refresh the list.
  RedrawItems(0, GetItemCount());
}

void LogListView::LogViewNewItems() {
  DCHECK_EQ(ui_loop_, MessageLoop::current());

  if (IsWindow()) {
    // Check if last item was previously visible...
    BOOL is_last_item_visible = ListView_IsItemVisible(m_hWnd,
                                                       GetItemCount() - 1);
    int num_rows = log_view_->GetNumRows();
    SetItemCountEx(num_rows, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    // We want to show the latest items if the
    // previously latest one was visible.
    if (is_last_item_visible)
      EnsureVisible(num_rows - 1, TRUE /* PartialOK */);
  }
}

void LogListView::LogViewCleared() {
  DCHECK_EQ(ui_loop_, MessageLoop::current());
  DeleteAllItems();
}

void LogListView::UpdateCommandStatus(bool has_focus) {
  bool has_selection = GetSelectedCount() != 0;

  update_ui_->UIEnable(ID_EDIT_COPY, has_focus && has_selection);
  update_ui_->UIEnable(ID_EDIT_SELECT_ALL, has_focus);
  update_ui_->UIEnable(ID_EDIT_CLEAR_ALL, has_focus);
  update_ui_->UIEnable(ID_EDIT_FIND, has_focus);
  update_ui_->UIEnable(ID_EDIT_FIND_NEXT, has_focus &&
                       !find_params_.expression_.empty());
  update_ui_->UIEnable(ID_EDIT_AUTOSIZE_COLUMNS,
                       has_focus && log_view_->GetNumRows());
}
