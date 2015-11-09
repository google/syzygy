// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/types/test_typenames.h"

// Used for entrypoint on test_typenames.dll to minimize symbol clutter.
extern "C" short __stdcall EntryPoint(void* instance,
                                      unsigned long reason,
                                      void* reserved) {
  testing::AliasTypes();
  return 1;
}

// This function is exported from the DLL for the sole purpose of producing
// an import library.
extern "C" void DummyExport() {
}
