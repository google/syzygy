// Copyright 2011 Google Inc.
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
// About dialog.
#include "sawdust/app/sawdust_about.h"
#include "base/logging.h"
#include "base/stringprintf.h"

#include "sawdust/app/resource.h"

AboutSawdustDialog::AboutSawdustDialog(HINSTANCE module,
                                       const TracerController& controller,
                                       const TracerConfiguration& config)
    : module_(module), controller_(controller), configuration_object_(config) {
  dialog_on_stack_ = true;
}

AboutSawdustDialog::~AboutSawdustDialog() {
  dialog_on_stack_ = false;
}

bool AboutSawdustDialog::dialog_on_stack_ = false;

int AboutSawdustDialog::DoModal(HWND hwnd_parent) {
  return ::DialogBoxParam(module_, MAKEINTRESOURCE(IDD_ABOUT), hwnd_parent,
                          DlgProc, reinterpret_cast<LPARAM>(this));
}

INT_PTR CALLBACK AboutSawdustDialog::DlgProc(HWND hwnd, UINT message,
                                             WPARAM wparam, LPARAM lparam) {
  bool handled = false;
  switch (message) {
    case WM_INITDIALOG: {
      AboutSawdustDialog* dlg = reinterpret_cast<AboutSawdustDialog*>(lparam);
      DCHECK(dlg != NULL);
      // Populate texts and resize as required.
      if (dlg) {
        std::wstring status_info_text;
        GetAppStateDescription(dlg->controller_,
                               dlg->configuration_object_,
                               &status_info_text);
        ::SetWindowText(::GetDlgItem(hwnd, IDC_STATUS),
                        status_info_text.c_str());
      }

      handled = true;
      break;
    }
    case WM_COMMAND: {
      WORD command = LOWORD(wparam);
      WORD event_code = HIWORD(wparam);
      switch (command) {
        case IDOK:
        case IDCANCEL:
          ::EndDialog(hwnd, 1);
          handled = true;
          break;
      }
    }
  }

  return static_cast<INT_PTR>(handled);
}

void AboutSawdustDialog::GetAppStateDescription(
    const TracerController& controller,
    const TracerConfiguration& config,
    std::wstring* description) {
  DCHECK(description != NULL);

  std::wstring upload_tgt;
  bool upload_is_remote = false;
  std::wstring trace_app_name;

  config.GetTracedApplication(&trace_app_name);

  if (controller.IsRunning()) {
    base::SStringPrintf(description,
                        L"Sawdust is now listening to events from %ls.\r\n\r\n",
                        trace_app_name.c_str());

    FilePath path_name;
    if (controller.GetCurrentEventLogFileName(&path_name)) {
      base::StringAppendF(description,
                          L"Application log is written to:  %ls\r\n\r\n",
                          path_name.value().c_str());
    }

    if (controller.GetCurrentKernelEventLogFileName(&path_name)) {
      base::StringAppendF(description,
                          L"Kernel log is written to: %ls\r\n\r\n",
                          path_name.value().c_str());
    }
  } else {
    base::SStringPrintf(
        description,
        L"Sawdust is configured to collect events from %ls.\r\n\r\n",
        trace_app_name.c_str());
  }

  if (config.GetUploadPath(&upload_tgt, &upload_is_remote)) {
    if (upload_is_remote)
      (*description) += L"Upload target URL is ";
    else
      (*description) += L"On upload request log data will be put in ";

    (*description) += upload_tgt.c_str();
  } else {
    (*description) += L"Upload target has not been defined.";
  }
}
