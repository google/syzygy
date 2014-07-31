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
#include "sawbuck/viewer/stack_trace_list_view.h"

#include <atlframe.h>
#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "sawbuck/viewer/const_config.h"

namespace {

const int kNoItem = -1;

}  // namespace

using base::StringPrintf;

const StackTraceListView::ColumnInfo StackTraceListView::kColumns[] = {
  { 72, L"Address" },
  { 90, L"Module" },
  { 180, L"File" },
  { 42, L"Line" },
  { 180, L"Function" },
};

const wchar_t* StackTraceListView::kConfigKeyName =
    config::kSettingsKey;
const wchar_t* StackTraceListView::kColumnOrderValueName =
    config::kStackTraceColumnOrder;
const wchar_t* StackTraceListView::kColumnWidthValueName =
    config::kStackTraceColumnWidths;

StackTraceListView::StackTraceListView(CUpdateUIBase* update_ui)
    : update_ui_(update_ui), lookup_service_(NULL), pid_(0) {
  COMPILE_ASSERT(arraysize(kColumns) == COL_MAX,
                 wrong_number_of_column_names);
}

void StackTraceListView::SetSymbolLookupService(
    ISymbolLookupService* lookup_service) {
  lookup_service_ = lookup_service;
}

void StackTraceListView::SetStackTrace(sym_util::ProcessId pid,
                                       const base::Time& time,
                                       size_t num_traces,
                                       void* traces[]) {
  pid_ = pid;
  time_ = time;

  // Cancel any in-progress symbol resolutions.
  TraceList::iterator it(trace_.begin());
  for (; it != trace_.end(); ++it)
    CancelResolution(&*it);

  trace_.clear();
  for (size_t i = 0; i < num_traces; ++i)
    trace_.push_back(TraceItem(traces[i]));

  DeleteAllItems();

  // Clear the old stack trace and get the new one.
  SetItemCount(trace_.size());

  for (size_t i = 0; i < trace_.size(); ++i) {
    int item = InsertItem(i, LPSTR_TEXTCALLBACK);

    for (int col = COL_MODULE; col < COL_MAX; ++col) {
      SetItem(item, 1, LVIF_TEXT, LPSTR_TEXTCALLBACK, 0, 0, 0, NULL);
    }
  }
}

LRESULT StackTraceListView::OnCreate(UINT msg,
                                     WPARAM wparam,
                                     LPARAM lparam,
                                     BOOL& handled) {
  // Call through to the original window class first.
  LRESULT ret = DefWindowProc(msg, wparam, lparam);

  AddColumns();

  // Tweak our extended styles.
  SetExtendedListViewStyle(LVS_EX_HEADERDRAGDROP |
                           LVS_EX_FULLROWSELECT |
                           LVS_EX_INFOTIP |
                           LVS_EX_DOUBLEBUFFER);

  return ret;
}

void StackTraceListView::OnDestroy() {
  SaveColumns();
}

LRESULT StackTraceListView::OnGetDispInfo(NMHDR* pnmh) {
  NMLVDISPINFO *info = reinterpret_cast<NMLVDISPINFO*>(pnmh);
  int col = info->item.iSubItem;
  size_t row = info->item.iItem;

  sym_util::Address address = trace_[row].address_;

  if (col == COL_ADDRESS) {
    item_text_ = StringPrintf(L"0x%08llX", address);
  } else {
    EnsureResolution(&trace_[row]);

    switch (col) {
      case COL_MODULE:
        item_text_ = L"Resolving...";
        break;

      case COL_FILE:
      case COL_LINE:
      case COL_SYMBOL:
        item_text_ = L"...";
        break;

      default:
        NOTREACHED();
        break;
    }
  }

  if (info->item.mask & LVIF_TEXT) {
    // Ask the list view to cache the result.
    info->item.mask |= LVIF_DI_SETITEM;
    info->item.pszText = const_cast<LPWSTR>(item_text_.c_str());
  }

  return 0;
}

LRESULT StackTraceListView::OnItemChanged(NMHDR* pnmh) {
  return 0;
}

void StackTraceListView::EnsureResolution(TraceItem* item) {
  DCHECK(item != NULL);
  if (item->lookup_handle_ != ISymbolLookupService::kInvalidHandle)
    return;

  DCHECK(lookup_service_ != NULL);
  item->lookup_handle_ = lookup_service_->ResolveAddress(
      pid_, time_, item->address_,
      base::Bind(&StackTraceListView::SymbolResolved,
                 base::Unretained(this)));
}

void StackTraceListView::CancelResolution(TraceItem* item) {
  DCHECK(item != NULL);
  if (item->lookup_handle_ == ISymbolLookupService::kInvalidHandle)
    return;

  DCHECK(lookup_service_ != NULL);
  lookup_service_->CancelRequest(item->lookup_handle_);
  item->lookup_handle_ = ISymbolLookupService::kInvalidHandle;
}

void StackTraceListView::SymbolResolved(sym_util::ProcessId pid,
    base::Time time, sym_util::Address address,
    ISymbolLookupService::Handle handle, const sym_util::Symbol& symbol) {

  size_t row = 0;
  for (; row < trace_.size(); ++row) {
    if (trace_[row].lookup_handle_ == handle)
      break;
  }

  // We should always find our associated handle.
  DCHECK(trace_[row].lookup_handle_ == handle);
  // No longer pending, make sure we don't cancel it later.
  trace_[row].lookup_handle_ = ISymbolLookupService::kInvalidHandle;

  for (int col = COL_MODULE; col < COL_MAX; ++col) {
    std::wstring item_text;
    switch (col) {
      case COL_MODULE:
        item_text = symbol.module.c_str();
        break;
      case COL_FILE:
        item_text = symbol.file.c_str();
        break;

      case COL_LINE:
        if (symbol.line != 0)
          item_text = StringPrintf(L"%d", symbol.line);
        break;

      case COL_SYMBOL:
        if (!symbol.name.empty() && symbol.offset != 0) {
          item_text = StringPrintf(L"%ls+0x%X",
                                    symbol.name.c_str(),
                                    symbol.offset);
        } else {
          item_text = symbol.name.c_str();
        }
        break;

      default:
        NOTREACHED();
        break;
    }

    SetItemText(row, col, item_text.c_str());
  }
}

void StackTraceListView::OnCopyCommand(UINT code, int id, CWindow window) {
  std::wstringstream selection;

  int item = GetNextItem(kNoItem, LVNI_SELECTED);
  for (; item != kNoItem; item = GetNextItem(item, LVNI_SELECTED)) {
    for (int col = COL_ADDRESS; col < COL_MAX; ++col) {
      wchar_t text[1024];
      GetItemText(item, col, text, arraysize(text));

      // Tab separate the columns.
      if (col != COL_ADDRESS)
        selection << L'\t';
      selection << text;
    }

    // Clipboard has CRLF separated lines.
    selection << L"\r\n";
  }

  // Copy the string to a global pointer for the clipboard.
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

void StackTraceListView::OnSelectAll(UINT code, int id, CWindow window) {
  // Select all items.
  SetItemState(kNoItem, LVIS_SELECTED, LVIS_SELECTED);
}

void StackTraceListView::UpdateCommandStatus(bool has_focus) {
  bool has_selection = GetSelectedCount() != 0;

  update_ui_->UIEnable(ID_EDIT_COPY, has_focus && has_selection);
  update_ui_->UIEnable(ID_EDIT_SELECT_ALL, has_focus);
  update_ui_->UIEnable(ID_EDIT_AUTOSIZE_COLUMNS, has_focus && trace_.size());
}

void StackTraceListView::OnSetFocus(CWindow window) {
  UpdateCommandStatus(true);

  // Give the list view a chance at the message.
  SetMsgHandled(FALSE);
}

void StackTraceListView::OnKillFocus(CWindow window) {
  UpdateCommandStatus(false);

  // Give the list view a chance at the message.
  SetMsgHandled(FALSE);
}

void StackTraceListView::OnAutoSizeColumns(UINT code, int id, CWindow window) {
  int columns = GetHeader().GetItemCount();
  for (int i = 0; i < columns; ++i)
    SetColumnWidth(i, LVSCW_AUTOSIZE);
}
