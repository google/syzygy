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

#include "syzygy/kasko/dll_lifetime.h"

#include "base/at_exit.h"
#include "base/logging_win.h"

namespace kasko {

class DllLifetime::Core : public base::RefCounted<DllLifetime::Core> {
 public:
  // Returns a reference to the single Core instance, creating it if necessary.
  static scoped_refptr<Core> Get();

 private:
  friend class base::RefCounted<Core>;

  Core();
  ~Core();

  // The exit manager is in charge of calling the dtors of singletons.
  base::AtExitManager exit_manager_;

  // The single Core instance.
  static Core* instance_;

  DISALLOW_COPY_AND_ASSIGN(Core);
};

DllLifetime::Core* DllLifetime::Core::instance_ = nullptr;

namespace {
// Use the same log facility as Chrome for convenience.
// {3A8A3990-64BC-4143-AEAF-0AA1A0123BCB}
static const GUID kKaskoTraceProviderName = {
    0x3a8a3990,
    0x64bc,
    0x4143,
    {0xae, 0xaf, 0xa, 0xa1, 0xa0, 0x12, 0x3b, 0xcb}};
}  // namespace

DllLifetime::DllLifetime() : core_(DllLifetime::Core::Get()) {
}

DllLifetime::~DllLifetime() {
}

// static
scoped_refptr<DllLifetime::Core> DllLifetime::Core::Get() {
  if (!instance_)
    instance_ = new Core();
  return scoped_refptr<Core>(instance_);
}

DllLifetime::Core::Core() {
  logging::LogEventProvider::Initialize(kKaskoTraceProviderName);
}

DllLifetime::Core::~Core() {
  logging::LogEventProvider::Uninitialize();
  DCHECK_EQ(this, instance_);
  instance_ = nullptr;
}

}  // namespace kasko
