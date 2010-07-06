// Copyright 2010 Google Inc.
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
// Filter dialog implementation.
#ifndef SAWBUCK_VIEWER_FILTER_DIALOG_H_
#define SAWBUCK_VIEWER_FILTER_DIALOG_H_

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlframe.h>
#include <string>
#include <vector>

#include "sawbuck/viewer/filter.h"
#include "sawbuck/viewer/list_view_base.h"
#include "sawbuck/viewer/resource.h"

// Traits specialization for filter list view.
typedef CWinTraits<WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS |
    LVS_REPORT | LVS_SHOWSELALWAYS | LVS_EX_FULLROWSELECT, 0>
        FilterListViewTraits;

// Class that wraps the list view on the filter dialog.
class FilterListView : public ListViewBase<FilterListView,
                                           FilterListViewTraits> {
  BEGIN_MSG_MAP_EX(FilterListView)
    MESSAGE_HANDLER(WM_CREATE, OnCreate)
  END_MSG_MAP()

  FilterListView();

  LRESULT OnCreate(UINT msg, WPARAM wparam, LPARAM lparam, BOOL& handled);

 public:
  // Our column definitions and config data to satisfy our contract
  // to the ListViewImpl superclass.
  static const ColumnInfo kColumns[];
  static const wchar_t* kConfigKeyName;
  static const wchar_t* kColumnOrderValueName;
  static const wchar_t* kColumnWidthValueName;

 protected:
  // The columns our list view displays.
  // @note COL_MAX must be equal to arraysize(kColumns).
  enum Columns {
    COL_COLUMN,
    COL_RELATION,
    COL_VALUE,
    COL_ACTION,
    // Must be last.
    COL_MAX,
  };
};


class FilterDialog: public CDialogImpl<FilterDialog>,
                    public CDialogResize<FilterDialog> {
 public:
  BEGIN_MSG_MAP(FilterDialog)
    MSG_WM_INITDIALOG(OnInitDialog)
    MSG_WM_CLOSE(OnClose)
    MSG_WM_DESTROY(OnDestroy)
    COMMAND_ID_HANDLER_EX(IDC_FILTER_ADD, OnFilterAdd)
    COMMAND_ID_HANDLER_EX(IDC_FILTER_REMOVE, OnFilterRemove)
    COMMAND_ID_HANDLER_EX(IDC_FILTER_RESET, OnFilterReset)
    COMMAND_ID_HANDLER_EX(IDOK, OnIdOk)
    COMMAND_ID_HANDLER_EX(IDCANCEL, OnIdCancel)
    CHAIN_MSG_MAP(CDialogResize<FilterDialog>)
  END_MSG_MAP()

  BEGIN_DLGRESIZE_MAP(FilterDialog)
    DLGRESIZE_CONTROL(IDOK, DLSZ_MOVE_X | DLSZ_MOVE_Y)
    DLGRESIZE_CONTROL(IDCANCEL, DLSZ_MOVE_X | DLSZ_MOVE_Y)
    DLGRESIZE_CONTROL(IDC_FILTER_ADD, DLSZ_MOVE_X)
    DLGRESIZE_CONTROL(IDC_FILTER_REMOVE, DLSZ_MOVE_X)
    DLGRESIZE_CONTROL(IDC_FILTER_TEXT, DLSZ_SIZE_X)
    DLGRESIZE_CONTROL(IDC_FILTER_ACTION, DLSZ_MOVE_X)
    DLGRESIZE_CONTROL(IDC_FILTER_LIST, DLSZ_SIZE_X | DLSZ_SIZE_Y)
    DLGRESIZE_CONTROL(IDC_FILTER_STATIC, DLSZ_MOVE_X)
  END_DLGRESIZE_MAP()

  static const int IDD = IDD_FILTERDIALOG;

  static const wchar_t* kColumns[];
  static const wchar_t* kRelations[];
  static const wchar_t* kActions[];

  std::vector<Filter> get_filters() { return filters_; }

 private:
  BOOL OnInitDialog(CWindow focus_window, LPARAM init_param);
  void OnClose();
  void OnDestroy();
  void OnIdOk(UINT notify_code, int id, CWindow window);
  void OnIdCancel(UINT notify_code, int id, CWindow window);
  void OnFilterAdd(UINT notify_code, int id, CWindow window);
  void OnFilterRemove(UINT notify_code, int id, CWindow window);
  void OnFilterReset(UINT notify_code, int id, CWindow window);

  void PopulateFilterList();

  int current_filter_;
  std::vector<Filter> filters_;

  FilterListView filter_list_view_;

  CComboBox column_dropdown_;
  CComboBox relation_dropdown_;
  CComboBox action_dropdown_;
  CComboBox value_dropdown_;

  CButton add_filter_button_;
  CButton remove_filter_button_;
  CButton reset_filter_button_;
};

#endif  // SAWBUCK_VIEWER_FILTER_DIALOG_H_
