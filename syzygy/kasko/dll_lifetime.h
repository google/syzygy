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

#ifndef SYZYGY_KASKO_DLL_LIFETIME_H_
#define SYZYGY_KASKO_DLL_LIFETIME_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"

namespace kasko {

// Sets up and tears down global Kasko DLL state. Multiple instances may safely
// exist simultaneously. Global state is set up when the first instance is
// constructed and torn down when the last instance is destroyed. Construction
// and destruction is not thread-safe.
class DllLifetime {
 public:
  DllLifetime();
  ~DllLifetime();

 private:
  // Holds global Kasko DLL state. Only a single Core instance will exist at any
  // time.
  class Core;

  // A refcount to prevent the global Core instance from being destroyed while
  // this DllLifetime is alive.
  scoped_refptr<Core> core_;

  DISALLOW_COPY_AND_ASSIGN(DllLifetime);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_DLL_LIFETIME_H_
