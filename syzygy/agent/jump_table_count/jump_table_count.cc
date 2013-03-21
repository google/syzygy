// Copyright 2013 Google Inc. All Rights Reserved.
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
// Implementation of the jump table entry count agent library.

#include "syzygy/agent/jump_table_count/jump_table_count.h"

#include "base/at_exit.h"
#include "base/logging.h"

extern "C" void __declspec(naked) _jump_table_case_counter() {
  __asm {
    // This is expected to be called via instrumentation that looks like:
    //    push case_id
    //    call [_jump_table_case_counter]
    //
    // Stack: ... case_id, ret_addr.

    // TODO(sebmarchand): Implement this function.
    ret 4
  }
}

extern "C" void __declspec(naked) _indirect_penter_dllmain() {
  __asm {
    // TODO(sebmarchand): Implement this function.
    ret 4
  }
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  // Our AtExit manager required by base.
  static base::AtExitManager* at_exit = NULL;

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      DCHECK(at_exit == NULL);
      at_exit = new base::AtExitManager();

      LOG(INFO) << "Initialized jump table entry count agent library.";
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      DCHECK(at_exit != NULL);
      delete at_exit;
      at_exit = NULL;
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}
