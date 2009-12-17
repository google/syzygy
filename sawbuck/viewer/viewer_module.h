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
#ifndef SAWBUCK_VIEWER_VIEWER_MODULE_H_
#define SAWBUCK_VIEWER_VIEWER_MODULE_H_

#include <atlbase.h>
#include <atlapp.h>

class SawbuckAppModule: public CAppModule {
 public:
  // Override Init and term to init/uninit COM.
  HRESULT Init(ATL::_ATL_OBJMAP_ENTRY* obj_map,
               HINSTANCE instance,
               const GUID* lib_id);
  void Term();
};

extern SawbuckAppModule g_sawbuck_app_module;

#endif  // SAWBUCK_VIEWER_VIEWER_MODULE_H_
