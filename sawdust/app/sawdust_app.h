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
// Log viewer module declaration.
#ifndef SAWDUST_APP_SAWDUST_APP_H_
#define SAWDUST_APP_SAWDUST_APP_H_

#include <windows.h>
#include <ShellAPI.h>

#include <string>

#include "base/scoped_ptr.h"
#include "base/threading/thread.h"
#include "base/time.h"
#include "sawdust/tracer/configuration.h"
#include "sawdust/tracer/controller.h"
#include "sawdust/tracer/upload.h"

class Task;
// A convenient wrapper for all things related to the application root.
class SawdustApplication {
 public:
  explicit SawdustApplication(HINSTANCE instance);
  ~SawdustApplication();

  HRESULT Initialize(int cmd_show);

 protected:
  HRESULT InitializeSysTrayApp(int cmd_show);
  HRESULT InitializeConfiguration();
  void OnUploadInvoked();
  void OnAboutInvoked();
  void OnExitInvoked();
  void OnMainMenuDisplayRequest(HWND hwnd, const POINT& click_point);
  void OrderlyShutdown(bool suppress_cleanup);
  void OnTooltipUpdateRequest();
  void OnNotificationDisplayRequest();
  void OnErrorNotificationRequest(const std::wstring& error_message);

 private:
  class UploadTask;

  enum UpdateTip {
    UPDATE_TIP = 0,
    SKIP_TIP,
  };

  enum ShowBalloon {
    SHOW_BALLOON = 0,
    DONT_SHOW_BALLOON,
  };

  static SawdustApplication* GetWindowData(HWND hwnd);
  void InvokeUploadTask(UploadTask* task);
  void StartLogging();
  void OnGuiUpdateRequest(UpdateTip update_tip, ShowBalloon show_balloon,
                          std::wstring message);
  static LRESULT CALLBACK WndProc(HWND hWnd, UINT message,
                                  WPARAM wParam, LPARAM lParam);

  // Windowing-related data.
  HINSTANCE current_instance_;
  HMENU tray_menu_;
  NOTIFYICONDATA icon_data_;
  HWND main_hwnd_;
  bool exiting_;

  // Actual data entries.
  TracerConfiguration configuration_object_;
  TracerController controller_;

  // Threading related. Note that since all operations are scheduled from the
  // same thread (GUI) there is no need for locks guarding upload. Note that
  // the controller may be accessed from multiple threads and needs to deal
  // with that.
  Task* upload_task_;
  base::Thread upload_thread_;

  MessageLoop* main_message_loop_;
  DISALLOW_COPY_AND_ASSIGN(SawdustApplication);
};

#endif  // SAWDUST_APP_SAWDUST_APP_H_
