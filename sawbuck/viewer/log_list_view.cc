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
#include "base/logging.h"
#include "base/i18n/time_formatting.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/log_lib/process_info_service.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/resource.h"
#include "sawbuck/viewer/stack_trace_list_view.h"

namespace {

const char* GetSeverityText(UCHAR severity) {
  switch (severity)  {
    case TRACE_LEVEL_NONE:
      return "NONE";
    case TRACE_LEVEL_FATAL:
      return "FATAL";
    case TRACE_LEVEL_ERROR:
      return "ERROR";
    case TRACE_LEVEL_WARNING:
      return "WARNING";
    case TRACE_LEVEL_INFORMATION:
      return "INFORMATION";
    case TRACE_LEVEL_VERBOSE:
      return "VERBOSE";
    case TRACE_LEVEL_RESERVED6:
      return "RESERVED6";
    case TRACE_LEVEL_RESERVED7:
      return "RESERVED7";
    case TRACE_LEVEL_RESERVED8:
      return "RESERVED8";
    case TRACE_LEVEL_RESERVED9:
      return "RESERVED9";
  }

  return "UNKNOWN";
}

// Returns true iff state indicates a selected listview item.
bool IsSelected(UINT state) {
  return (state & LVIS_SELECTED) == LVIS_SELECTED;
}

const int kNoItem = -1;

}  // namespace

using base::StringPrintf;

const LogListView::ColumnInfo LogListView::kColumns[] = {
  { 24, L"Severity" },
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


LogViewFormatter::LogViewFormatter() {
}

bool LogViewFormatter::FormatColumn(ILogView* log_view,
                                    int row,
                                    Column col,
                                    std::string* str) {
  DCHECK(log_view != NULL);
  DCHECK(str != NULL);

  switch (col) {
    case SEVERITY:
      *str = GetSeverityText(log_view->GetSeverity(row));
      break;

    case PROCESS_ID:
      *str = StringPrintf("%d", log_view->GetProcessId(row));
      break;

    case THREAD_ID:
      *str = StringPrintf("%d", log_view->GetThreadId(row));
      break;

    case TIME:
      {
        if (!base_time_.is_null()) {
          base::Time row_time = log_view->GetTime(row);
          base::TimeDelta time_delta = row_time - base_time_;
          bool is_negative = false;

          if (time_delta.ToInternalValue() < 0) {
            is_negative = true;
            time_delta = -time_delta;
          }

          int64 hours = time_delta.InHours();
          int64 minutes = time_delta.InMinutes() % 60;
          int64 seconds = time_delta.InSeconds() % 60;
          int64 milliseconds = time_delta.InMilliseconds() % 1000;

          if (is_negative) {
            *str = StringPrintf("-%02lld:%02lld:%02lld-%03lld",
                                hours, minutes, seconds, milliseconds);
          } else {
            *str = StringPrintf("%02lld:%02lld:%02lld-%03lld",
                                hours, minutes, seconds, milliseconds);
          }
        } else {
          base::Time time = log_view->GetTime(row);
          base::Time::Exploded exploded;
          time.LocalExplode(&exploded);
          *str = StringPrintf("%02d:%02d:%02d-%03d",
                              exploded.hour,
                              exploded.minute,
                              exploded.second,
                              exploded.millisecond);
        }
      }
      break;

    case FILE:
      *str = log_view->GetFileName(row);
      break;

    case LINE:
      *str = StringPrintf("%d", log_view->GetLine(row));
      break;

    case MESSAGE:
      *str = log_view->GetMessage(row);
      break;

    default:
      return false;
      break;
  }

  return true;
}

LogListView::LogListView(CUpdateUIBase* update_ui)
    : log_view_(NULL), event_cookie_(0),
      update_ui_(update_ui), stack_trace_view_(NULL),
      process_info_service_(NULL) {
  ui_loop_ = base::MessageLoop::current();

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

  if (col == COL_SEVERITY && info->item.mask & LVIF_IMAGE) {
    info->item.iImage =
        GetImageIndexForSeverity(log_view_->GetSeverity(row));
  }

  std::string temp_text;
  formatter_.FormatColumn(log_view_,
                          row,
                          static_cast<LogViewFormatter::Column>(col),
                          &temp_text);

  item_text_ = base::UTF8ToWide(temp_text);
  base::TrimWhitespace(item_text_, base::TRIM_TRAILING, &item_text_);

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
  int col = -1;
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
    LVHITTESTINFO hit_test = { client_point };
    row = SubItemHitTest(&hit_test);
    col = hit_test.iSubItem;
  }

  CMenu menu;
  if (!menu.CreatePopupMenu()) {
    LOG(ERROR) << "Unable to create popup menu";
    return;
  }

  menu.AppendMenu(row == -1 ? MF_GRAYED : MF_ENABLED,
                  ID_SET_TIME_ZERO,
                  L"&Set Base Time");

  menu.AppendMenu(formatter_.base_time().is_null() ? MF_GRAYED : MF_ENABLED,
                  ID_RESET_BASE_TIME,
                  L"&Reset Base Time");

  // TODO(siggi): Implement popup menu items to include/exclude
  //      the clicked column by its value.
#if 0
  if (row != -1 && col != -1) {
    std::wstring column = kColumns[col].title;
    StringToLowerASCII(column);
    std::wstring item_text = StringPrintf(L"&Include %ls \"%ls\"",
                                          column.c_str(),
                                          L"foo");
    menu.AppendMenu(MF_ENABLED,
                    ID_INCLUDE_COLUMN,
                    item_text.c_str());

    item_text = StringPrintf(L"&Exclude %ls \"%ls\"",
                             column.c_str(),
                             L"foo");
    menu.AppendMenu(MF_ENABLED,
                    ID_EXCLUDE_COLUMN,
                    item_text.c_str());
  }
#endif

  const UINT kMenuFlags = TPM_LEFTALIGN | TPM_VCENTERALIGN | TPM_RIGHTBUTTON |
                          TPM_HORPOSANIMATION | TPM_VERPOSANIMATION;
  menu.TrackPopupMenu(0, point.x, point.y, wnd);
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
  formatter_.set_base_time(log_view_->GetTime(row));

  // Refresh the list.
  RedrawItems(0, GetItemCount());
}

void LogListView::OnResetBaseTime(UINT code, int id, CWindow window) {
  formatter_.set_base_time(base::Time());

  // Refresh the list.
  RedrawItems(0, GetItemCount());
}

void LogListView::LogViewNewItems() {
  DCHECK_EQ(ui_loop_, base::MessageLoop::current());

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
  DCHECK_EQ(ui_loop_, base::MessageLoop::current());
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
