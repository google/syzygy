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
// Log viewer module declaration.
#include "sawbuck/viewer/viewer_module.h"
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/i18n/icu_util.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/message_loop/message_pump.h"
#include "base/message_loop/message_pump_win.h"
#include "sawbuck/viewer/viewer_window.h"

#include <initguid.h>  // NOLINT
#include "sawbuck/viewer/sawbuck_guids.h"  // NOLINT

HRESULT SawbuckAppModule::Init(ATL::_ATL_OBJMAP_ENTRY* obj_map,
                               HINSTANCE instance,
                               const GUID* lib_id) {
  HRESULT hr = ::OleInitialize(NULL);
  if (FAILED(hr))
    return hr;

  return CAppModule::Init(obj_map, instance, lib_id);
}

void SawbuckAppModule::Term() {
  CAppModule::Term();
  ::OleUninitialize();
}

SawbuckAppModule g_sawbuck_app_module;

// This class makes a Frankenstein wedding between the WTL and the Chrome
// base message loop classes. Dispatching events through the Chrome base
// message loop from the main UI thread allows us to use the very nice
// task primitives to dispatch work back to the UI thread. WTL on
// the other hand, requires a CMessageLoop (derivative) to dispatch
// Window events, which is how we get this ... well ... abomination.
class HybridMessageLoopObserver
    : public CMessageLoop,
      public base::MessagePumpDispatcher,
      public base::MessageLoop::TaskObserver {
 public:
  HybridMessageLoopObserver() : idle_scheduled_(false) {
  }

  // @name base::MessagePumpDispatcher implementation.
  // Implemented to hook in WTL PreTranslateMessage.
  // @{
  virtual uint32_t Dispatch(const base::NativeEvent& event) OVERRIDE;
  // @}

  // @name base::MessageLoop::TaskObserver implementation.
  // Implemented to keep a task out for WTL idle processing.
  // @{
  virtual void WillProcessTask(const base::PendingTask& pending_task) OVERRIDE;
  virtual void DidProcessTask(const base::PendingTask& pending_task) OVERRIDE;
  // @}

 private:
  void MaybeScheduleIdleTask();
  void OnIdleTask();

  bool idle_scheduled_;
};

uint32_t HybridMessageLoopObserver::Dispatch(const base::NativeEvent& event) {
  // Make sure menus, toolbars and such are updated after event is handled.
  MaybeScheduleIdleTask();

  return POST_DISPATCH_PERFORM_DEFAULT;
}

void HybridMessageLoopObserver::WillProcessTask(
    const base::PendingTask& pending_task) {
  // Make sure we idle to update menus and such after each task or batch of
  // tasks has been handled.
  MaybeScheduleIdleTask();
}

void HybridMessageLoopObserver::DidProcessTask(
    const base::PendingTask& pending_task) {
  // Intentionally empty.
}

void HybridMessageLoopObserver::MaybeScheduleIdleTask() {
  // Keep zero or one task outstanding at any time.
  if (idle_scheduled_)
    return;

  idle_scheduled_ = true;
  base::MessageLoop::current()->PostNonNestableTask(
      FROM_HERE, base::Bind(&HybridMessageLoopObserver::OnIdleTask,
                            base::Unretained(this)));
}

void HybridMessageLoopObserver::OnIdleTask() {
  idle_scheduled_ = false;

  // Perform idle processing and re-schedule if we had some work.
  if (OnIdle(0))
    MaybeScheduleIdleTask();
}

int APIENTRY wWinMain(HINSTANCE instance,
                      HINSTANCE prev_instance,
                      LPTSTR /*cmd_line*/,
                      int show) {
  CommandLine::Init(0, NULL);
  base::AtExitManager at_exit;

  // Initialize ICU.
  CHECK(base::i18n::InitializeICU());

  // Init logging to no file logging.
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_NONE;
  logging::InitLogging(settings);
  logging::LogEventProvider::Initialize(kSawbuckLogProvider);

  ::OleInitialize(NULL);
  ::InitCommonControls();

  g_sawbuck_app_module.Init(NULL, instance, NULL);

  // Initialize the WTL message loop hookup.
  HybridMessageLoopObserver observer;
  g_sawbuck_app_module.AddMessageLoop(&observer);

  // Instantiate the base message loop, and plumb the WTL hookup.
  base::MessageLoopForUI message_loop;
  message_loop.AddTaskObserver(&observer);

  ViewerWindow window;
  window.CreateEx();
  window.ShowWindow(show);
  window.UpdateWindow();

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  if (cmd_line->HasSwitch("import")) {
    std::vector<std::wstring> files(cmd_line->GetArgs());
    std::vector<base::FilePath> paths;
    for (size_t i = 0; i < files.size(); ++i) {
      paths.push_back(base::FilePath(files[i]));
    }
    window.ImportLogFiles(paths);
  } else if (cmd_line->HasSwitch("start-capture")) {
    window.SetCapture(true);
  }

  // Run the ugly, hybrid message loop with the observer/dispatcher.
  base::RunLoop run_loop(&observer);
  run_loop.Run();

  g_sawbuck_app_module.RemoveMessageLoop();

  g_sawbuck_app_module.Term();

  return 0;
}
