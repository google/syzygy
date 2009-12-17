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
#include "sawbuck/viewer/viewer_window.h"
#include <initguid.h>

//
// SystemTraceControlGuid. Used to specify event tracing for kernel
//
DEFINE_GUID( /* 9e814aad-3204-11d2-9a82-006008a86939 */
    SystemTraceControlGuid,
    0x9e814aad,
    0x3204,
    0x11d2,
    0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39
  );

// {C43B1318-C63D-465b-BCF4-7A89A369F8ED}
DEFINE_GUID(kSawbuckLogProvider,
    0xc43b1318,
    0xc63d,
    0x465b,
    0xbc, 0xf4, 0x7a, 0x89, 0xa3, 0x69, 0xf8, 0xed
  );

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


int APIENTRY wWinMain(HINSTANCE instance,
                      HINSTANCE prev_instance,
                      LPTSTR cmd_line,
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

  CMessageLoop msg_loop;
  g_sawbuck_app_module.AddMessageLoop(&msg_loop);

  ViewerWindow window;
  window.CreateEx();
  window.ShowWindow(show);
  window.UpdateWindow();

  int ret = msg_loop.Run();

  g_sawbuck_app_module.RemoveMessageLoop();

  g_sawbuck_app_module.Term();

  return ret;
}

// TODO(siggi): figure a better way to do this.
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")  // NOLINT
