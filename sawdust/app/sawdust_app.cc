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
#include "sawdust/app/sawdust_app.h"
#include <CommCtrl.h>

#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "base/message_loop.h"
#include "base/path_service.h"
#include "base/stringprintf.h"
#include "sawdust/app/sawdust_about.h"
#include "sawdust/app/report.h"
#include "sawdust/tracer/com_utils.h"

#include "sawdust/app/resource.h"


#define WM_USER_SHELLICON WM_USER + 1
#define MAX_RESOURCESTRING_LEN 128

DISABLE_RUNNABLE_METHOD_REFCOUNT(SawdustApplication);

namespace {
const wchar_t kConfigurationFileTitle[] = L"sawdust.json";
const wchar_t kMessageBoxTitle[] = L"Google Sawdust";
const wchar_t kGenericStartupError[] = L"The program could not start.";
const wchar_t kNoConfigError[] = L"Configuration file (sawdust.json) not found."
    L" Sawdust cannot start.";
const wchar_t kCantReadConfig[]  = L"Configuration file (sawdust.json) can't "
    L"be read. Sawdust cannot start.";
const wchar_t kCantStart[]  = L"The trace collection routine did not start "
    L"correctly. The program will now exit.";
const char kUploadThreadId[] = "DataCompressionAndUpload";
const wchar_t kAskSave[] = L"Background logging has accumulated over %d "
    L"minutes worth of log data. Should it be uploaded to the log server?";
const wchar_t kDefaultBaloonText[] = L"Sawdust has started and is now "
    L"collecting log data.";
const wchar_t kActivityLogFmt[] = L"%s\nLogging program activity "
    L"(started %d %s ago).";
const wchar_t kActivityUploadFmt[] = L"%s\n%s to %s.";
const wchar_t kDoneUploadFmt[] = L"Log data has been %s to %s.%s";
const wchar_t kUploadFailureFmt[] = L"The program encountered an error while "
    L"trying to %s data to %s.%s";
const wchar_t kLoggingRestarts[] = L"\nLoging will now restart";
const wchar_t kUploadRetry[] = L"\nRetrying...";
const unsigned int kTooltipUpdateElapse = 15000;  // Every 15 seconds.

template<size_t N>
bool LoadStringSafe(HINSTANCE instance, UINT id, wchar_t (&string)[N]) {
  int copy_count = ::LoadString(instance, id, string, N - 1);
  if (copy_count <= 0) {
    NOTREACHED() << "Resource %d not found." << id;
    return false;
  }

  if (copy_count == N - 1)
    string[N - 1] = 0;

  return true;
}
}

// Encapsulation of the upload task. Uses controller embedded in the application
// object. Includes a cleanup task.
class SawdustApplication::UploadTask : public Task {
 public:
  UploadTask(Task* post_close_task, SawdustApplication* parent_object)
      : close_task_(post_close_task), the_app_(parent_object), hr_(S_OK) {
    DCHECK(the_app_ != NULL);
  }

  // Initialize (create) the uploader. Does not include the access to actual
  // streams.
  HRESULT Initialize() {
    std::wstring target_uri;
    bool assume_remote;
    if (!the_app_->configuration_object_.GetUploadPath(&target_uri,
                                                       &assume_remote)) {
      NOTREACHED() << "Cannot upload - the target is not defined.";
      return E_FAIL;
    }
    uploader_.reset(new ReportUploader(target_uri, !assume_remote));
    return S_OK;
  }

  // Invoke the 'upload' routine. Note that streams with input data will be
  // opened 'on demand', which also may report in an error.
  void Run() {
    DCHECK(uploader_ != NULL);

    if (uploader_ != NULL) {
      the_app_->main_message_loop_->PostTask(FROM_HERE,
          NewRunnableMethod(the_app_, &SawdustApplication::OnGuiUpdateRequest,
                            false, true, std::wstring()));

      ReportContent content;
      hr_ = content.Initialize(the_app_->controller_,
                               the_app_->configuration_object_);
      if (SUCCEEDED(hr_)) {
        the_app_->main_message_loop_->PostTask(FROM_HERE,
            NewRunnableMethod(the_app_, &SawdustApplication::OnGuiUpdateRequest,
                              false, true, std::wstring()));

        hr_ = uploader_->Upload(&content);

        if (FAILED(hr_) && uploader_->GetArchivePath(NULL)) {
          // Post an error message first.
          std::wstring message;
          FormErrorString(&message, true);
          the_app_->main_message_loop_->PostTask(FROM_HERE,
              NewRunnableMethod(the_app_,
                  &SawdustApplication::OnGuiUpdateRequest,
                      false, false, message));
          hr_ = uploader_->UploadArchive();
        }
        if (SUCCEEDED(hr_)) {
          the_app_->main_message_loop_->PostTask(FROM_HERE,
              NewRunnableMethod(the_app_,
                  &SawdustApplication::OnGuiUpdateRequest,
                      true, true, std::wstring()));
        } else {
          std::wstring message;
          FormErrorString(&message, false);
          the_app_->main_message_loop_->PostTask(FROM_HERE,
              NewRunnableMethod(the_app_,
                  &SawdustApplication::OnGuiUpdateRequest,
                      false, false, message));
        }
      }
    } else {
      NOTREACHED() << "Could not start upload task. " <<
          (uploader_ == NULL ?
           "Not initialized properly." : "Already pending.");
      hr_ = E_UNEXPECTED;
    }

    the_app_->upload_task_ = NULL;  // We won't need it there anymore.
    // The above might be a race, but benign. upload_task_ is also used to
    // enable / disable the menu command launching upload, but in conjunction
    // controller_.IsProcessing which itself is synchronized.

    if (close_task_ != NULL) {
      the_app_->main_message_loop_->PostTask(FROM_HERE, close_task_.release());
    }
  }

  void FormErrorString(std::wstring* error_string, bool permit_retry) {
    std::wstring upload_url;
    bool remote_target = false;
    if (the_app_->configuration_object_.GetUploadPath(&upload_url,
                                                      &remote_target)) {
      bool retry_possible = uploader_->GetArchivePath(NULL) && permit_retry;
      wchar_t error_msg[201];
      swprintf_s(error_msg, 200, kUploadFailureFmt,
                 remote_target ? L"upload" : L"compress", upload_url.c_str(),
                 retry_possible ? kUploadRetry : L"");
      *error_string = error_msg;
    } else {
      *error_string = L"Log data could not be uploaded to the server.";
    }
  }

 private:
  scoped_ptr<Task> close_task_;
  scoped_ptr<ReportUploader> uploader_;
  SawdustApplication* the_app_;
  HRESULT hr_;
};


SawdustApplication::SawdustApplication(HINSTANCE instance)
  : tray_menu_(NULL), current_instance_(NULL), main_hwnd_(NULL),
    upload_thread_(kUploadThreadId), exiting_(false), upload_task_(NULL) {
  current_instance_ = instance;
  ::memset(&icon_data_, 0, sizeof(icon_data_));
}

SawdustApplication::~SawdustApplication() {
  if (tray_menu_ != NULL)
    ::DestroyMenu(tray_menu_);

  if (icon_data_.hIcon != NULL)
    ::DestroyIcon(icon_data_.hIcon);
}

LRESULT CALLBACK SawdustApplication::WndProc(HWND hwnd, UINT message,
                                             WPARAM wparam, LPARAM lparam) {
  bool process_default = true;
  switch (message) {
    case WM_CREATE: {
      CREATESTRUCT* create_data = reinterpret_cast<CREATESTRUCT*>(lparam);
      if (create_data != NULL && create_data->lpCreateParams != NULL) {
        LONG_PTR insert_ptr =
            reinterpret_cast<LONG_PTR>(create_data->lpCreateParams);
        ::SetWindowLongPtr(hwnd, GWLP_USERDATA, insert_ptr);

        // Now set up the link going the other way.
        SawdustApplication* app = reinterpret_cast<SawdustApplication*>(
            create_data->lpCreateParams);
        app->main_hwnd_ = hwnd;
      }
      break;
    }
    case WM_USER_SHELLICON:
      switch (LOWORD(lparam)) {
        case WM_RBUTTONDOWN: {
          SawdustApplication* app = GetWindowData(hwnd);
          POINT click_point;
          click_point.x = click_point.y = 0;
          if (!::GetCursorPos(&click_point))
            NOTREACHED() << "Failed to get cursor coordinates. Weird!";
          else if (app != NULL)
            app->OnMainMenuDisplayRequest(hwnd, click_point);
          process_default = true;
          break;
        }
      }
      break;
    case WM_COMMAND: {
      WORD command = LOWORD(wparam);
      WORD event_code = HIWORD(wparam);
      SawdustApplication* app = GetWindowData(hwnd);
      process_default = false;
      DCHECK(NULL != app);
      if (app == NULL)
        return 0;

      switch (command) {
        case ID_ABOUT:
          app->OnAboutInvoked();
          break;
        case ID_UPLOAD:
          app->OnUploadInvoked();
          break;
        case ID_EXIT_ON_FAILURE:
          ::MessageBox(hwnd, kCantStart, kMessageBoxTitle, MB_OK);
          app->OrderlyShutdown(false);
          break;
        case ID_EXIT:
          app->OnExitInvoked();
          break;
        }
      break;
    }
    case WM_TIMER: {
      SawdustApplication* app = GetWindowData(hwnd);
      if (lparam == NULL && app != NULL &&
          reinterpret_cast<WPARAM>(app) == wparam) {
        app->OnTooltipUpdateRequest();
      }
      break;
    }
    case WM_DESTROY:
      MessageLoop::current()->Quit();
      break;
  }

  if (process_default)
    return DefWindowProc(hwnd, message, wparam, lparam);
  else
    return 0;
}

SawdustApplication* SawdustApplication::GetWindowData(HWND hwnd) {
  SawdustApplication* app_data =
      reinterpret_cast<SawdustApplication*>(
          ::GetWindowLongPtr(hwnd, GWLP_USERDATA));
  DCHECK(app_data != NULL) << "No window data.";
  DCHECK(app_data == NULL || app_data->main_hwnd_ == hwnd);
  return app_data;
}

// Initialize the Windows application aspect. Creates the window, loads
// necessary resource items and places the visible gadget in the sys tray.
HRESULT SawdustApplication::InitializeSysTrayApp(int cmd_show) {
  TCHAR window_class[MAX_RESOURCESTRING_LEN];
  TCHAR window_title[MAX_RESOURCESTRING_LEN];

  if (!LoadStringSafe(current_instance_, IDS_WINCLASS, window_class))
    return E_FAIL;

  if (!LoadStringSafe(current_instance_, IDS_APP_TITLE, window_title))
    return E_FAIL;

  WNDCLASS window_registration = {};

  window_registration.style = CS_HREDRAW | CS_VREDRAW;
  window_registration.lpfnWndProc = WndProc;
  window_registration.cbClsExtra = 0;
  window_registration.cbWndExtra = 0;
  window_registration.hInstance = current_instance_;
  window_registration.hIcon = LoadIcon(current_instance_,
                                       MAKEINTRESOURCE(IDR_SYS_TRAY));
  window_registration.hCursor = LoadCursor(NULL, IDC_ARROW);
  window_registration.hbrBackground =
      reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  window_registration.lpszMenuName = MAKEINTRESOURCE(IDR_SYSTRAYMENU);
  window_registration.lpszClassName = window_class;
  ATOM reg_atom = ::RegisterClass(&window_registration);

  if (reg_atom == NULL) {
    LOG(ERROR) << "Failed to register window class. " << com::LogWe();
    return E_FAIL;
  }

  HWND hwnd = CreateWindow(window_class, window_title, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, current_instance_, this);

  if (!hwnd) {
    LOG(ERROR) << "Failed to create the main window. " << com::LogWe();
    return E_FAIL;
  }

  icon_data_.cbSize = sizeof(icon_data_);
  icon_data_.hWnd = hwnd;
  icon_data_.uID = IDR_SYS_TRAY;
  icon_data_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
  icon_data_.uCallbackMessage = WM_USER_SHELLICON;

  if (!LoadStringSafe(current_instance_, IDS_APPTOOLTIP, icon_data_.szTip))
    return E_FAIL;

  ::LoadIconMetric(current_instance_, (LPCTSTR)MAKEINTRESOURCE(IDR_SYS_TRAY),
                   LIM_SMALL, &icon_data_.hIcon);

  if (!LoadStringSafe(current_instance_, IDS_APPTOOLTIP,
                      icon_data_.szInfoTitle)) {
    return E_FAIL;
  }

  wcscpy_s(icon_data_.szInfo, 240, kDefaultBaloonText);  // 240 per API specs.
  icon_data_.dwInfoFlags = NIIF_INFO;

  if (!::Shell_NotifyIcon(NIM_ADD, &icon_data_)) {
    LOG(ERROR)  << "Failed to place SysStay icon. " << com::LogWe();
    return E_FAIL;  // The app would be useless, may as well quit now.
  }

  tray_menu_ = ::LoadMenu(current_instance_, MAKEINTRESOURCE(IDR_SYSTRAYMENU));
  if (NULL == tray_menu_)  {
    LOG(ERROR) << "Failed to load menu. " << com::LogWe();
    return E_FAIL;  // The app would be useless, may as well quit now.
  }

  // Set up the timer for tooltip status refreshes.
  if (::SetTimer(main_hwnd_, reinterpret_cast<UINT_PTR>(this),
                 kTooltipUpdateElapse, NULL) == 0) {
    LOG(ERROR)  << "Failed to start update timer. " << com::LogWe();
  }

  return S_OK;
}

// Initializes configuration of the tool from the settings file. The function
// involves file IO and possibly user interaction.
HRESULT SawdustApplication::InitializeConfiguration() {
  FilePath exe_location;
  PathService::Get(base::FILE_EXE, &exe_location);
  FilePath config_path = exe_location.DirName().Append(kConfigurationFileTitle);

  if (!file_util::PathExists(config_path)) {
    ::MessageBox(NULL, kNoConfigError, kMessageBoxTitle, MB_OK);
    return E_FAIL;
  }

  std::string json_config_content;
  if (!file_util::ReadFileToString(config_path, &json_config_content)) {
    ::MessageBox(NULL, kCantReadConfig, kMessageBoxTitle, MB_OK);
    return E_FAIL;
  }

  std::string error_text;
  if (!configuration_object_.Initialize(json_config_content,
                                        exe_location.DirName(), &error_text)) {
    std::wstring error_message(error_text.begin(), error_text.end());
    ::MessageBox(NULL, error_message.c_str(), kMessageBoxTitle, MB_OK);
    return E_FAIL;
  }

  return S_OK;
}

HRESULT SawdustApplication::Initialize(int cmd_show) {
  HRESULT hr = InitializeConfiguration();
  if (FAILED(hr))
    return hr;

  main_message_loop_ = MessageLoop::current();
  DCHECK(NULL != main_message_loop_);
  hr = InitializeSysTrayApp(cmd_show);

  if (FAILED(hr)) {
    // InitializeConfiguration takes care of displaying its own messages.
    // To make the experience consistent (even if unpleasant), a generic error
    // message is displayed here.
    ::MessageBox(NULL, kGenericStartupError,
                 kMessageBoxTitle, MB_OK | MB_ICONERROR);

    return hr;
  }

  main_message_loop_->PostTask(FROM_HERE,
      NewRunnableMethod(this, &SawdustApplication::StartLogging));

  return hr;
}

// Close all ongoing processing (synchronous) before dismissing the application.
// There is no return value, as it is not clear what the caller would do in case
// of failure. Errors shall be logged.
void SawdustApplication::OrderlyShutdown(bool suppress_cleanup) {
  KillTimer(main_hwnd_, reinterpret_cast<UINT_PTR>(this));

  if (controller_.IsRunning()) {
    HRESULT hr = controller_.Stop();
    DCHECK(SUCCEEDED(hr)) <<
        "There was trouble shutting down. " << com::LogHr(hr);
  }

  if (!suppress_cleanup) {
    // By design, controller doesn't own 'result files' once it has been
    // stopped. Normally, they are taken over by the reporter. However, if the
    // reported never got invoked, they may be left over. We will remove them
    // here unless specifically told not to do so.
    FilePath file_to_remove;
    if (controller_.GetCompletedEventLogFileName(&file_to_remove) &&
        file_util::PathExists(file_to_remove)) {
      file_util::Delete(file_to_remove, false);
    }

    if (controller_.GetCompletedKernelEventLogFileName(&file_to_remove) &&
        file_util::PathExists(file_to_remove)) {
      file_util::Delete(file_to_remove, false);
    }
  }

  // Upload thread should be empty by now. Stop it.
  DCHECK(upload_task_ == NULL);
  if (upload_thread_.IsRunning())
    upload_thread_.Stop();

  ::Shell_NotifyIcon(NIM_DELETE, &icon_data_);
  ::DestroyWindow(main_hwnd_);
}

// Response to the 'upload' menu command. We will stop the current logging
// process and commence upload. Once the process has been completed, the logging
// process shall be restarted.
void SawdustApplication::OnUploadInvoked() {
  // Instance of upload task with re-start task to boot.
  InvokeUploadTask(new UploadTask(
      NewRunnableMethod(this, &SawdustApplication::StartLogging), this));
}

void SawdustApplication::InvokeUploadTask(UploadTask* task) {
  DCHECK(controller_.IsRunning());
  DCHECK(upload_task_ == NULL);

  if (controller_.IsRunning() && upload_task_ == NULL) {
    HRESULT hr = controller_.Stop();  // Stop immediately!
    if (FAILED(hr)) {
      NOTREACHED() << "Failed to stop logging. Can't upload! hr=0x" <<
        std::hex << hr;
      return;
    }

    if (!upload_thread_.IsRunning()) {
      base::Thread::Options start_options(MessageLoop::TYPE_IO, 0);
      if (!upload_thread_.StartWithOptions(start_options)) {
        NOTREACHED() << "Failed to start the upload thread!";
      }
    }

    if SUCCEEDED(task->Initialize()) {
      upload_task_ = task;
      upload_thread_.message_loop()->PostTask(FROM_HERE, upload_task_);
    } else {
      NOTREACHED() << "Failed to initialize upload task. Will not start.";
    }
  }
}

// Handle user's application exit request. If the controller is running and
// has accumulated enough data, we will give the user upload action (question
// through a message box).
void SawdustApplication::OnExitInvoked() {
  bool shutdown_with_upload = false;
  exiting_ = true;

  TracerConfiguration::ExitAction exit_step =
      configuration_object_.ActionOnExit();

  if (controller_.IsLogWorthSaving()) {
    // The controller appears to be running and there is some worthwhile unsaved
    // data. If the settings say we should try and upload - let's try.
    if (exit_step == TracerConfiguration::REPORT_ASK) {
      std::wstring disp_message =
          base::StringPrintf(kAskSave,
              controller_.GetLoggingTimeSpan().InMinutes());
      shutdown_with_upload = ::MessageBox(main_hwnd_, disp_message.c_str(),
                                          kMessageBoxTitle,
                                          MB_YESNO | MB_ICONQUESTION) == IDYES;
    } else {
      shutdown_with_upload  = exit_step == TracerConfiguration::REPORT_AUTO;
    }
  }

  if (shutdown_with_upload) {
    InvokeUploadTask(new UploadTask(
        NewRunnableMethod(this, &SawdustApplication::OrderlyShutdown, false),
            this));
  } else {
    OrderlyShutdown(exit_step == TracerConfiguration::REPORT_NONE);
  }
}

// The function sets enabled / disabled flags on menu items and displays it.
void SawdustApplication::OnMainMenuDisplayRequest(HWND hwnd,
                                                  const POINT& click_point) {
  HMENU popup_menu = ::GetSubMenu(tray_menu_, 0);

  // Check if there is an upload pending.
  bool upload_allowed = upload_task_ == NULL && controller_.IsRunning();

  MENUITEMINFO menu_item = {};
  menu_item.cbSize = sizeof(menu_item);
  menu_item.fMask = MIIM_STATE;

  menu_item.fState = upload_allowed && !exiting_ ? MFS_ENABLED : MFS_DISABLED;
  SetMenuItemInfo(popup_menu, ID_UPLOAD, FALSE, &menu_item);

  menu_item.fState = !exiting_ ? MFS_ENABLED : MFS_DISABLED;
  SetMenuItemInfo(popup_menu, ID_EXIT, FALSE, &menu_item);

  menu_item.fState = AboutSawdustDialog::IsDialogOnStack() ?
      MFS_DISABLED : MFS_ENABLED;
  ::SetMenuItemInfo(popup_menu, ID_ABOUT, FALSE, &menu_item);

  ::SetForegroundWindow(hwnd);
  ::TrackPopupMenu(popup_menu,
                   TPM_LEFTALIGN | TPM_LEFTBUTTON | TPM_BOTTOMALIGN,
                   click_point.x, click_point.y, 0 , hwnd, NULL);
}

// Construct an up-to-date mini-description and update application's tooltip
// text.
void SawdustApplication::OnTooltipUpdateRequest() {
  if (exiting_)
    return;

  // OK, Now that we have it here... We can be logging, uploading or idle.
  bool constructed = false;
  wchar_t tooltip_buffer[sizeof(icon_data_.szTip)];

  if (!LoadStringSafe(current_instance_, IDS_APPTOOLTIP, tooltip_buffer)) {
    tooltip_buffer[0] = 0;  // Use empty string in this unlikely scenario.
  }

  const size_t wsize = sizeof(icon_data_.szTip) /
                       sizeof(*icon_data_.szTip) - 1;
  bool remote = false;
  std::wstring upload_url;
  if (controller_.IsRunning()) {
    // Logging.
    base::TimeDelta logtime = controller_.GetLoggingTimeSpan();
    const wchar_t* unit = L"minutes";
    int value = logtime.InMinutes();
    if (value == 0) {
      unit = L"seconds";
      value = static_cast<int>(logtime.InSeconds());
    } else if (value == 1) {
      unit = L"minute";
    }
    if (value > 0) {
      swprintf_s(icon_data_.szTip, wsize, kActivityLogFmt, tooltip_buffer,
                 value, unit);
      constructed = true;
    }
  } else if (upload_task_ != NULL &&
             configuration_object_.GetUploadPath(&upload_url, &remote)) {
    // Updating.
    swprintf_s(icon_data_.szTip, wsize, kActivityUploadFmt, tooltip_buffer,
               remote ? L"Uploading" : L"Compressing", upload_url.c_str());
    constructed = true;
  }

  // Idle or weird. Or both.
  if (!constructed)
    wcscpy_s(icon_data_.szTip, sizeof(icon_data_.szTip), tooltip_buffer);

  icon_data_.uFlags = NIF_TIP;
  if (!::Shell_NotifyIcon(NIM_MODIFY, &icon_data_)) {
    LOG(ERROR)  << "Failed to update SysTray icon. " << com::LogWe();
  }
}

// Show the app's balloon with the current info.
void SawdustApplication::OnNotificationDisplayRequest() {
  // A request to display a notification will mean that something has changed.
  // Right now, this 'something' can only be 'upload done'.
  bool remote = false;
  std::wstring upload_url;
  if (configuration_object_.GetUploadPath(&upload_url, &remote)) {
    const size_t wsize = sizeof(icon_data_.szInfo) /
                         sizeof(*icon_data_.szInfo) - 1;

    swprintf_s(icon_data_.szInfo, wsize, kDoneUploadFmt,
               remote ? L"uploaded" : L"placed", upload_url.c_str(),
               exiting_ ? L"" : kLoggingRestarts);
    icon_data_.uFlags = NIF_INFO;
    icon_data_.dwInfoFlags = NIIF_INFO;

    if (!::Shell_NotifyIcon(NIM_MODIFY, &icon_data_)) {
      LOG(ERROR)  << "Failed to update SysTray icon. " << com::LogWe();
    }
  }
}

// Show an error message in the app's balloon.
void SawdustApplication::OnErrorNotificationRequest(
    const std::wstring& error_message) {
  const size_t wsize = sizeof(icon_data_.szInfo) /
                       sizeof(*icon_data_.szInfo) - 1;
  wcscpy_s(icon_data_.szInfo, wsize, error_message.c_str());
  icon_data_.uFlags = NIF_INFO;
  icon_data_.dwInfoFlags = NIIF_ERROR;

  if (!::Shell_NotifyIcon(NIM_MODIFY, &icon_data_)) {
    LOG(ERROR)  << "Failed to update SysTray icon. " << com::LogWe();
  }
}

// Display the modal 'about' window.
void SawdustApplication::OnAboutInvoked() {
  if (!AboutSawdustDialog::IsDialogOnStack()) {
    AboutSawdustDialog box(current_instance_, controller_,
                           configuration_object_);
    box.DoModal(this->main_hwnd_);
  }
}

// Intended to be called as a task, which would start the controller when the
// application is starting.
void SawdustApplication::StartLogging() {
  HRESULT hr = controller_.Start(configuration_object_);
  if (FAILED(hr)) {
    // There is not much we can do. Display message and send exit command
    // to the host window.
    LOG(ERROR) << "Tracking failed to start. " << com::LogHr(hr);
    ::PostMessage(main_hwnd_, WM_COMMAND, MAKEWPARAM(ID_EXIT_ON_FAILURE, 0), 0);
  }
}

// Invoked as a task, takes care of displaying notifications to user
// (balloon, message box).
void SawdustApplication::OnGuiUpdateRequest(
    bool update_tip, bool show_balloon, std::wstring message) {
  if (update_tip)
    OnTooltipUpdateRequest();
  if (!message.empty())
    OnErrorNotificationRequest(message);
  else if (show_balloon)
    OnNotificationDisplayRequest();
}
