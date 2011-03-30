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
#ifndef SAWDUST_APP_SAWDUST_ABOUT_H_
#define SAWDUST_APP_SAWDUST_ABOUT_H_

#include <windows.h>
#include <string>

#include "sawdust/tracer/controller.h"

// A Windows dialog (About Sawdust).
class AboutSawdustDialog {
 public:
  AboutSawdustDialog(HINSTANCE module,
                     const TracerController& controller,
                     const TracerConfiguration& config);
  ~AboutSawdustDialog();

  // Display modal dialog.
  int DoModal(HWND hwnd_parent);

  // Indicates if a new dialog can/should be displayed.
  static bool IsDialogOnStack() {
    return dialog_on_stack_;
  }

  // Builds a human-readable description of the running instance's current
  // state, based on |controller| and |config|.
  static void GetAppStateDescription(const TracerController& controller,
                                     const TracerConfiguration& config,
                                     std::wstring* description);

 private:
  static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT message,
                                  WPARAM wparam, LPARAM lparam);

  HINSTANCE module_;
  const TracerController& controller_;
  const TracerConfiguration& configuration_object_;

  static bool dialog_on_stack_;
};

#endif  // SAWDUST_APP_SAWDUST_ABOUT_H_
