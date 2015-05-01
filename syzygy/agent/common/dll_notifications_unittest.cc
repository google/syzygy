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

#include "syzygy/agent/common/dll_notifications.h"

#include "base/bind.h"
#include "base/files/file_path.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace agent {
namespace common {

namespace {

using testing::_;
using testing::Eq;

class NotificationReceiver {
 public:
  MOCK_METHOD5(OnNotification,
               void(DllNotificationWatcher::EventType type,
                    HMODULE module,
                    size_t module_size,
                    const base::StringPiece16& dll_path,
                    const base::StringPiece16& dll_base_name));
};

class DllNotificationWatcherTest : public testing::Test {
 public:
  DllNotificationWatcherTest() : test_dll_(NULL) {
  }

  virtual void SetUp() override {
    test_dll_path_ = testing::GetExeRelativePath(L"test_dll.dll");
  }

  virtual void TearDown() override {
    if (test_dll_ != NULL) {
      ::FreeLibrary(test_dll_);
    }
  }

  void LoadTestDll() {
    test_dll_ = ::LoadLibrary(test_dll_path_.value().c_str());
    ASSERT_NE(static_cast<HMODULE>(NULL), test_dll_);
  }

  void UnloadTestDll() {
    ASSERT_NE(static_cast<HMODULE>(NULL), test_dll_);
    ASSERT_TRUE(::FreeLibrary(test_dll_));
    test_dll_ = NULL;
  }

  testing::StrictMock<NotificationReceiver> receiver_;
  base::FilePath test_dll_path_;
  HMODULE test_dll_;
};

}  // namespace

TEST_F(DllNotificationWatcherTest, Init) {
  DllNotificationWatcher watcher;

  ASSERT_TRUE(watcher.Init(
      base::Bind(&NotificationReceiver::OnNotification,
                 base::Unretained(&receiver_))));


  // We expect DLL load notifications for test_dll_ and its import dependency.
  EXPECT_CALL(receiver_,
              OnNotification(DllNotificationWatcher::kDllLoaded,
                             _, _,
                             testing::Eq(test_dll_path_.value()),
                             testing::Eq(test_dll_path_.BaseName().value())));
  EXPECT_CALL(receiver_,
              OnNotification(DllNotificationWatcher::kDllLoaded,
                             _, _,
                             _,
                             testing::Eq(L"export_dll.dll")));

  // Load the DLL.
  ASSERT_NO_FATAL_FAILURE(LoadTestDll());

  // Now we should see unload notification for the same DLLs.
  EXPECT_CALL(receiver_,
              OnNotification(DllNotificationWatcher::kDllUnloaded,
                             _, _,
                             testing::Eq(test_dll_path_.value()),
                             testing::Eq(test_dll_path_.BaseName().value())));
  EXPECT_CALL(receiver_,
              OnNotification(DllNotificationWatcher::kDllUnloaded,
                             _, _,
                             _,
                             testing::Eq(L"export_dll.dll")));
  UnloadTestDll();
}

TEST_F(DllNotificationWatcherTest, Reset) {
  DllNotificationWatcher watcher;

  ASSERT_TRUE(watcher.Init(
      base::Bind(&NotificationReceiver::OnNotification,
                 base::Unretained(&receiver_))));
  // Reset the watcher - this should unregister, and we should get no callbacks.
  watcher.Reset();

  // We should get no notifications after resetting.
  ASSERT_NO_FATAL_FAILURE(LoadTestDll());
  UnloadTestDll();
}

TEST_F(DllNotificationWatcherTest, ResetOnDeletion) {
  {
    DllNotificationWatcher watcher;

    ASSERT_TRUE(watcher.Init(
        base::Bind(&NotificationReceiver::OnNotification,
                   base::Unretained(&receiver_))));
  }

  // We should get no notifications after the instance goes out of scope.
  // We should get no notifications after resetting.
  ASSERT_NO_FATAL_FAILURE(LoadTestDll());
  UnloadTestDll();
}

}  // namespace common
}  // namespace agent
