// Copyright 2010 Google Inc.
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
// Symbol lookup service unittest.
#include "sawbuck/log_lib/symbol_lookup_service.h"

#include <vector>
#include <tlhelp32.h>
#include "base/bind.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/thread.h"
#include "base/win/pe_image.h"
#include "base/win/scoped_handle.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace {
void Foo() {
  NOTREACHED() << "This function is only here for an address to resolve";
}

void QuitMessageLoop(base::MessageLoop* loop) {
  loop->PostTask(FROM_HERE, base::MessageLoop::QuitClosure());
}

class SymbolLookupServiceTest: public testing::Test {
 public:
  SymbolLookupServiceTest() : background_thread_("Background Thread") {
  }

  virtual void SetUp() {
    ASSERT_TRUE(background_thread_.Start());
    service_.set_background_thread(background_thread_.message_loop());
  }

  virtual void TearDown() {
    background_thread_.Stop();
  }

  void LoadModules() {
    base::win::ScopedHandle snap(
        ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ::GetCurrentProcessId()));
    base::Time now(base::Time::Now());

    MODULEENTRY32 module = { sizeof(module) };
    ASSERT_TRUE(::Module32First(snap, &module));
    do {
      base::win::PEImage image(module.hModule);
      ASSERT_TRUE(image.VerifyMagic());

      sym_util::ModuleInformation module_info;

      module_info.base_address =
          reinterpret_cast<sym_util::ModuleBase>(module.modBaseAddr);
      module_info.module_size = module.modBaseSize;
      module_info.image_checksum =
          image.GetNTHeaders()->OptionalHeader.CheckSum;
      module_info.time_date_stamp =
          image.GetNTHeaders()->FileHeader.TimeDateStamp;
      module_info.image_file_name = module.szExePath;

      service_.OnModuleLoad(::GetCurrentProcessId(), now, module_info);

    } while (::Module32Next(snap, &module));
  }

  void ResolveAll() {
    // Chase the symbol lookups on the background thread
    // by posting a quit message to this message loop.
    background_thread_.message_loop()->PostTask(FROM_HERE,
        base::Bind(QuitMessageLoop, base::MessageLoop::current()));

    // And run our loop.
    message_loop_.Run();
  }
  void FooResolved(sym_util::ProcessId pid, base::Time time,
      sym_util::Address add, SymbolLookupService::Handle handle,
      const sym_util::Symbol& symbol) {
    EXPECT_EQ(&message_loop_, base::MessageLoop::current());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, L"Foo", symbol.name);

    resolved_.push_back(handle);
  }

  void FooNotResolved(sym_util::ProcessId pid, base::Time time,
      sym_util::Address add, SymbolLookupService::Handle handle,
      const sym_util::Symbol& symbol) {
    EXPECT_EQ(&message_loop_, base::MessageLoop::current());
    EXPECT_STREQ(L"", symbol.name.c_str());

    resolved_.push_back(handle);
  }

 protected:
  std::vector<SymbolLookupService::Handle> resolved_;

  base::MessageLoop message_loop_;
  base::Thread background_thread_;
  SymbolLookupService service_;
};

TEST_F(SymbolLookupServiceTest, LookupNoModules) {
  sym_util::Symbol symbol;

  SymbolLookupService::Handle h =
      service_.ResolveAddress(
          ::GetCurrentProcessId(), base::Time::Now(),
          reinterpret_cast<sym_util::Address>(&Foo),
          base::Bind(&SymbolLookupServiceTest::FooNotResolved,
                     base::Unretained(this)));

  ASSERT_NE(SymbolLookupService::kInvalidHandle, h);

  ResolveAll();

  ASSERT_EQ(1, resolved_.size());
}

TEST_F(SymbolLookupServiceTest, LookupFoo) {
  LoadModules();

  for (int i = 0; i < 10; ++i) {
    SymbolLookupService::Handle h =
        service_.ResolveAddress(
            ::GetCurrentProcessId(), base::Time::Now(),
            reinterpret_cast<sym_util::Address>(&Foo),
            base::Bind(&SymbolLookupServiceTest::FooResolved,
                       base::Unretained(this)));

    ASSERT_NE(SymbolLookupService::kInvalidHandle, h);
  }

  ResolveAll();

  ASSERT_EQ(10, resolved_.size());
}

TEST_F(SymbolLookupServiceTest, LookupFooCancel) {
  LoadModules();

  for (int i = 0; i < 10; ++i) {
    SymbolLookupService::Handle h =
        service_.ResolveAddress(
            ::GetCurrentProcessId(), base::Time::Now(),
            reinterpret_cast<sym_util::Address>(&Foo),
            base::Bind(&SymbolLookupServiceTest::FooResolved,
                       base::Unretained(this)));

    ASSERT_NE(SymbolLookupService::kInvalidHandle, h);

    if (i % 2)
      service_.CancelRequest(h);
  }

  ResolveAll();

  ASSERT_EQ(5, resolved_.size());
}

}  // namespace
