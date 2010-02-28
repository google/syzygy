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

#include "base/string_util.h"
#include "sawbuck/sym_util/symbol_cache.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/symbol_lookup_service.h"

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

StackTraceListView::StackTraceListView() : lookup_service_(NULL), pid_(0) {
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
  trace_.clear();
  for (size_t i = 0; i < num_traces; ++i)
    trace_.push_back(reinterpret_cast<sym_util::Address>(traces[i]));

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

  sym_util::Address address = trace_[row];

  if (col == COL_ADDRESS) {
    item_text_ = StringPrintf(L"0x%08llX", address);
  } else {
    sym_util::Symbol symbol;
    if (lookup_service_ != NULL) {
      // Note that even when this fails, it may return e.g. module information.
      lookup_service_->ResolveAddress(pid_, time_, address, &symbol);
    }

    switch (col) {
      case COL_MODULE:
        item_text_ = symbol.module.c_str();
        break;
      case COL_FILE:
        item_text_ = symbol.file.c_str();
        break;

      case COL_LINE:
        if (symbol.line != 0) {
          item_text_ = StringPrintf(L"%d", symbol.line);
        } else {
          item_text_.clear();
        }
        break;

      case COL_SYMBOL:
        if (!symbol.name.empty() && symbol.offset != 0) {
          item_text_ = StringPrintf(L"%ls+0x%X",
                                    symbol.name.c_str(),
                                    symbol.offset);
        } else {
          item_text_ = symbol.name.c_str();
        }
        break;

      default:
        item_text_ = L"UNKNOWN COLUMN";
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
