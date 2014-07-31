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
// Find dialog implementation.
#include "sawbuck/viewer/find_dialog.h"

#include <richedit.h>

#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"

FindDialog::FindDialog(const FindParameters& defaults) : params_(defaults) {
}

FindDialog::~FindDialog() {
}

LRESULT FindDialog::OnInitDialog(CWindow focus_window, LPARAM init_param) {
  SendDlgItemMessage(IDC_FIND_TEXT, EM_EXLIMITTEXT, 0, 1024);
  CheckDlgButton(IDC_MATCH_CASE,
      params_.match_case_ ? BST_CHECKED : BST_UNCHECKED);
  CheckRadioButton(IDC_DIRECTION_DOWN, IDC_DIRECTION_UP,
      params_.direction_down_ ? IDC_DIRECTION_DOWN : IDC_DIRECTION_UP);
  CWindow text_wnd(GetDlgItem(IDC_FIND_TEXT));
  text_wnd.SetFocus();
  if (!params_.expression_.empty()) {
    text_wnd.SetWindowText(base::UTF8ToWide(params_.expression_).c_str());
    text_wnd.SendMessage(EM_SETSEL, 0, -1);
  }
  return FALSE;
}

LRESULT FindDialog::OnFind(UINT notify_code, int id, CWindow window) {
  CWindow text_wnd(GetDlgItem(IDC_FIND_TEXT));
  base::win::ScopedBstr text;
  text_wnd.GetWindowText(text.Receive());
  if (text.Length()) {
    params_.match_case_ = (IsDlgButtonChecked(IDC_MATCH_CASE) == BST_CHECKED);
    params_.direction_down_ = (IsDlgButtonChecked(IDC_DIRECTION_DOWN) ==
                               BST_CHECKED);
    base::WideToUTF8(text, text.Length(), &params_.expression_);
    EndDialog(IDOK);
  } else {
    text_wnd.SetFocus();
  }
  return 0;
}

LRESULT FindDialog::OnCancel(UINT notify_code, int id, CWindow window) {
  EndDialog(IDCANCEL);
  return 0;
}
