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
// Stack trace list view window.
#ifndef SAWBUCK_VIEWER_STACK_TRACE_LIST_VIEW_H_
#define SAWBUCK_VIEWER_STACK_TRACE_LIST_VIEW_H_

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlctrls.h>
#include <atlmisc.h>
#include <string>
#include <vector>
#include "base/time/time.h"
#include "sawbuck/log_lib/symbol_lookup_service.h"
#include "sawbuck/viewer/list_view_base.h"
#include "sawbuck/viewer/resource.h"

// Fwd.
class ISymbolLookupService;

namespace WTL {
class CUpdateUIBase;
};

typedef CWinTraits<WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS |
    LVS_REPORT> StackTraceListViewTraits;

// List view control subclass that manages the stack trace view.
class StackTraceListView
    : public ListViewBase<StackTraceListView, StackTraceListViewTraits> {
 public:
  typedef ListViewBase<StackTraceListView, StackTraceListViewTraits> WindowBase;
  DECLARE_WND_SUPERCLASS(NULL, WindowBase::GetWndClassName())

  BEGIN_MSG_MAP_EX(LogList)
    MESSAGE_HANDLER(WM_CREATE, OnCreate)
    MSG_WM_DESTROY(OnDestroy)
    MSG_WM_SETFOCUS(OnSetFocus)
    MSG_WM_KILLFOCUS(OnKillFocus)
    COMMAND_ID_HANDLER_EX(ID_EDIT_AUTOSIZE_COLUMNS, OnAutoSizeColumns)
    COMMAND_ID_HANDLER_EX(ID_EDIT_COPY, OnCopyCommand)
    COMMAND_ID_HANDLER_EX(ID_EDIT_SELECT_ALL, OnSelectAll)
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_GETDISPINFO, OnGetDispInfo)
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_ITEMCHANGED, OnItemChanged)
    DEFAULT_REFLECTION_HANDLER()
  END_MSG_MAP()

  explicit StackTraceListView(CUpdateUIBase* update_ui);

  void SetSymbolLookupService(ISymbolLookupService* lookup_service);
  void SetStackTrace(sym_util::ProcessId pid,
                     const base::Time& time,
                     size_t num_traces,
                     void* traces[]);

  // Our column definitions and config data to satisfy our contract
  // to the ListViewImpl superclass.
  static const ColumnInfo kColumns[];
  static const wchar_t* kConfigKeyName;
  static const wchar_t* kColumnOrderValueName;
  static const wchar_t* kColumnWidthValueName;

 private:
  // The columns our list view displays.
  // @note COL_MAX must be equal to arraysize(kColumns).
  enum Columns {
    COL_ADDRESS,
    COL_MODULE,
    COL_FILE,
    COL_LINE,
    COL_SYMBOL,

    // Must be last.
    COL_MAX,
  };

  LRESULT OnCreate(UINT msg, WPARAM wparam, LPARAM lparam, BOOL& handled);
  void OnDestroy();
  void OnCopyCommand(UINT code, int id, CWindow window);
  void OnSelectAll(UINT code, int id, CWindow window);
  void OnSetFocus(CWindow window);
  void OnKillFocus(CWindow window);
  void OnAutoSizeColumns(UINT code, int id, CWindow window);

  void UpdateCommandStatus(bool has_focus);

  LRESULT OnGetDispInfo(NMHDR* notification);
  LRESULT OnItemChanged(NMHDR* notification);

  struct TraceItem {
    explicit TraceItem(void* address)
        : lookup_handle_(ISymbolLookupService::kInvalidHandle),
          address_(reinterpret_cast<sym_util::Address>(address)) {
    }

    // The lookup handle while a lookup is pending for address_.
    ISymbolLookupService::Handle lookup_handle_;
    sym_util::Address address_;
  };

  // Start resolving the address in item, unless it's already being resolved.
  void EnsureResolution(TraceItem* item);
  // Cancel any resolution pending for item.
  void CancelResolution(TraceItem* item);

  // Callback for symbol resolution.
  void SymbolResolved(sym_util::ProcessId pid, base::Time time,
      sym_util::Address address, ISymbolLookupService::Handle handle,
      const sym_util::Symbol& symbol);

  CUpdateUIBase* update_ui_;

  // The symbol lookup service we avail ourselves of.
  ISymbolLookupService* lookup_service_;

  // The current stack trace we're displaying.
  sym_util::ProcessId pid_;
  base::Time time_;
  typedef std::vector<TraceItem> TraceList;
  TraceList trace_;

  // Temporary storage for strings returned from OnGetDispInfo.
  std::wstring item_text_;
};

#endif  // SAWBUCK_VIEWER_STACK_TRACE_LIST_VIEW_H_
