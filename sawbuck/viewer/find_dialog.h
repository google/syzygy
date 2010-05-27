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
// Find dialog declaration.
#ifndef SAWBUCK_VIEWER_FIND_DIALOG_H_
#define SAWBUCK_VIEWER_FIND_DIALOG_H_

#include <atlbase.h>
#include <atlcrack.h>
#include <atlwin.h>
#include <string>
#include "resource.h"

struct FindParameters {
  FindParameters() : direction_down_(true), match_case_(false) {
  }

  // UTF8 encoded regular expression.
  std::string expression_;
  bool direction_down_;
  bool match_case_;
};

class FindDialog : public CDialogImpl<FindDialog> {
 public:
  enum { IDD = IDD_FINDDIALOG };

  BEGIN_MSG_MAP(FindDialog)
    MSG_WM_INITDIALOG(OnInitDialog)
    COMMAND_ID_HANDLER_EX(IDOK, OnFind)
    COMMAND_ID_HANDLER_EX(IDCANCEL, OnCancel)
  END_MSG_MAP()

  explicit FindDialog(const FindParameters& defaults);
  ~FindDialog();

  LRESULT OnInitDialog(CWindow focus_window, LPARAM init_param);
  LRESULT OnFind(UINT notify_code, int id, CWindow window);
  LRESULT OnCancel(UINT notify_code, int id, CWindow window);

  const FindParameters& find_params() const {
    return params_;
  }

 protected:
  FindParameters params_;
};

#endif  // SAWBUCK_VIEWER_FIND_DIALOG_H_
