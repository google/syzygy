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
#include <atlmisc.h>
#include <string>
#include <vector>
#include "base/basictypes.h"
#include "base/logging.h"
#include "resource.h"

// Forward declaration.
struct ProviderSettings;

// The log viewer window plays host to a listview, taking care of handling
// its notification requests etc.
class ProviderDialog
    : public CDialogImpl<ProviderDialog>,
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
    CHAIN_MSG_MAP(CCustomDraw<ProviderDialog>)
  END_MSG_MAP()

  ProviderDialog(size_t num_providers, ProviderSettings* settings);

  // We draw a dropdown arrow on item post-paint.
  DWORD OnPrePaint(int id, NMCUSTOMDRAW* cust);
  DWORD OnItemPrePaint(int id, NMCUSTOMDRAW* cust);
  DWORD OnItemPostPaint(int id, NMCUSTOMDRAW* cust);

 private:
  BOOL OnInitDialog(CWindow focus, LPARAM init_param);
  LRESULT OnOkCancel(WORD code, WORD id, HWND window, BOOL& handled);
  LRESULT OnProviderClick(NMHDR* pnmh);
  void OnContextMenu(CWindow wnd, CPoint point);
  void DrawDropDown(NMLVCUSTOMDRAW* lv_cust);
  void DoPopupMenu(int item);

  // The list view control that displays the providers.
  CListViewCtrl providers_;

  // The row that's currently displaying a popup menu.
  int pushed_row_;

  // Number of providers pointed to by settings_.
  size_t num_providers_;
  ProviderSettings* settings_;
};

#endif  // SAWBUCK_VIEWER_PROVIDER_DIALOG_H_
