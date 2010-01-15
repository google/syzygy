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
#include "base/time.h"
#include "sawbuck/sym_util/types.h"
#include "sawbuck/viewer/list_view_base.h"

class ISymbolLookupService {
 public:
  // Resolve an address from a given process at a given time to
  // a symbol.
  // @returns true iff successful.
  virtual bool ResolveAddress(sym_util::ProcessId process_id,
                              const base::Time& time,
                              sym_util::Address address,
                              sym_util::Symbol* symbol) = 0;
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
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_GETDISPINFO, OnGetDispInfo)
    REFLECTED_NOTIFY_CODE_HANDLER_EX(LVN_ITEMCHANGED, OnItemChanged)
    DEFAULT_REFLECTION_HANDLER()
  END_MSG_MAP()

  StackTraceListView();

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

  LRESULT OnGetDispInfo(NMHDR* notification);
  LRESULT OnItemChanged(NMHDR* notification);

  // The symbol lookup service we avail ourselves of.
  ISymbolLookupService* lookup_service_;

  // The current stack trace we're displaying.
  sym_util::ProcessId pid_;
  base::Time time_;
  std::vector<sym_util::Address> trace_;

  // Temporary storage for strings returned from OnGetDispInfo.
  std::wstring item_text_;
};

#endif  // SAWBUCK_VIEWER_STACK_TRACE_LIST_VIEW_H_
