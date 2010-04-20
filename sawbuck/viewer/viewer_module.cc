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
#include "base/logging.h"
#include "base/logging_win.h"
#include "base/message_loop.h"
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

// This class is a Frankenstein wedding between the WTL and the Chrome
// base message loop classes. Dispatching events through the Chrome base
// message loop from the main UI thread allows us to use the very nice
// task primitives to dispatch work back to the UI thread. WTL on
// the other hand, requires a CMessageLoop (derivative) to dispatch
// Window events, which is how we get this ... well ... abomination.
class HybridMessageLoop
    : public CMessageLoop,
      public MessageLoopForUI,
      public MessageLoop::Dispatcher {
 public:
  using MessageLoopForUI::Run;

  HybridMessageLoop() {
  }

  virtual bool DoWork() {
    return MessageLoopForUI::DoWork();
  }

  virtual bool Dispatch(const MSG& msg) {
    if (msg.message == WM_QUIT)
      return false;

    m_msg = msg;
    if (!PreTranslateMessage(&m_msg)) {
      ::TranslateMessage(&m_msg);
      ::DispatchMessage(&m_msg);
    }

    return true;
  }

  bool DoIdleWork() {
    if (OnIdle(0))
      return true;

    return MessageLoopForUI::DoIdleWork();
  }
};

int APIENTRY wWinMain(HINSTANCE instance,
                      HINSTANCE prev_instance,
                      LPTSTR /*cmd_line*/,
                      int show) {
  CommandLine::Init(0, NULL);
  base::AtExitManager at_exit;

  // Init logging to no file logging.
  logging::InitLogging(NULL,
                       logging::LOG_NONE,
                       logging::DONT_LOCK_LOG_FILE,
                       logging::DELETE_OLD_LOG_FILE);
  logging::LogEventProvider::Initialize(kSawbuckLogProvider);

  ::OleInitialize(NULL);
  ::InitCommonControls();

  g_sawbuck_app_module.Init(NULL, instance, NULL);

  HybridMessageLoop hybrid;
  g_sawbuck_app_module.AddMessageLoop(&hybrid);

  ViewerWindow window;
  window.CreateEx();
  window.ShowWindow(show);
  window.UpdateWindow();

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  if (cmd_line->HasSwitch("import")) {
    std::vector<std::wstring> files(cmd_line->GetLooseValues());
    std::vector<FilePath> paths;
    for (size_t i = 0; i < files.size(); ++i) {
      paths.push_back(FilePath(files[i]));
    }
    window.ImportLogFiles(paths);
  } else if (cmd_line->HasSwitch("start-capture")) {
    window.SetCapture(true);
  }

  hybrid.Run(&hybrid);

  g_sawbuck_app_module.RemoveMessageLoop();

  g_sawbuck_app_module.Term();

  return 0;
}
