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
// Provider dialog declaration.
#ifndef SAWBUCK_VIEWER_PROVIDER_DIALOG_H_
#define SAWBUCK_VIEWER_PROVIDER_DIALOG_H_

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlctrls.h>
#include <atlframe.h>
#include <atlmisc.h>
#include "sawbuck/viewer/provider_configuration.h"
#include "resource.h"  // NOLINT

// The log viewer window plays host to a listview, taking care of handling
// its notification requests etc.
class ProviderDialog
    : public CDialogImpl<ProviderDialog>,
      public CDialogResize<ProviderDialog>,
      public CCustomDraw<ProviderDialog> {
 public:
  typedef CDialogImpl<ProviderDialog> SuperDialog;
  static const int IDD = IDD_PROVIDERDIALOG;

  BEGIN_MSG_MAP_EX(ProviderDialog)
    COMMAND_ID_HANDLER(IDOK, OnOkCancel)
    COMMAND_ID_HANDLER(IDCANCEL, OnOkCancel)
    MSG_WM_CONTEXTMENU(OnContextMenu)
    NOTIFY_HANDLER_EX(IDC_PROVIDERS, NM_CLICK, OnProviderClick)
    MSG_WM_INITDIALOG(OnInitDialog)
    CHAIN_MSG_MAP(CDialogResize<ProviderDialog>)
    CHAIN_MSG_MAP(CCustomDraw<ProviderDialog>)
  END_MSG_MAP()

  BEGIN_DLGRESIZE_MAP(ProviderDialog)
    DLGRESIZE_CONTROL(IDC_PROVIDERS, DLSZ_SIZE_X | DLSZ_SIZE_Y)
    DLGRESIZE_CONTROL(IDOK, DLSZ_MOVE_X | DLSZ_MOVE_Y)
    DLGRESIZE_CONTROL(IDCANCEL, DLSZ_MOVE_X | DLSZ_MOVE_Y)
  END_DLGRESIZE_MAP()

  explicit ProviderDialog(ProviderConfiguration* settings);

  // We draw the dropdown arrows on item post-paint.
  DWORD OnPrePaint(int id, NMCUSTOMDRAW* cust);
  DWORD OnItemPrePaint(int id, NMCUSTOMDRAW* cust);
  DWORD OnItemPostPaint(int id, NMCUSTOMDRAW* cust);

 private:
  enum Columns {
    COL_NAME = 0,
    COL_LEVEL,
    COL_ENABLE_BITS,
    COL_MAX
  };

  BOOL OnInitDialog(CWindow focus, LPARAM init_param);
  LRESULT OnOkCancel(WORD code, WORD id, HWND window, BOOL& handled);
  LRESULT OnProviderClick(NMHDR* pnmh);
  void OnContextMenu(CWindow wnd, CPoint point);
  void DrawDropDowns(NMLVCUSTOMDRAW* lv_cust);
  void DrawDropDown(NMLVCUSTOMDRAW* lv_cust, int col);
  void DoPopupMenu(int item, int col);
  void DoProviderPopupMenu(int item);
  void DoEnableBitsPopupMenu(int item);

  // The list view control that displays the providers.
  CListViewCtrl providers_;

  // The row and col currently displaying a popup menu.
  int pushed_row_;
  int pushed_col_;
  // Number of providers pointed to by settings_.
  size_t num_providers_;
  ProviderConfiguration* settings_;
};

#endif  // SAWBUCK_VIEWER_PROVIDER_DIALOG_H_
