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

#include "syzygy/trace/common/service.h"

#include "base/bind.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace trace {
namespace common {

namespace {

using testing::_;
using testing::Invoke;
using testing::Return;

const wchar_t kTestServiceName[] = L"TestService";

class TestService : public Service {
 public:
  TestService() : Service(kTestServiceName) { }

  // Initially we leave the callbacks empty. This plumbs the callbacks into our
  // base class.
  void SetCallbacks() {
    set_started_callback(base::Bind(&InvokeStartedCallback));
    set_interrupted_callback(base::Bind(&InvokeInterruptedCallback));
    set_stopped_callback(base::Bind(&InvokeStoppedCallback));
  }

  MOCK_METHOD0(StartImpl, bool());
  MOCK_METHOD0(StopImpl, bool());
  MOCK_METHOD0(JoinImpl, bool());

  // Testing seam callback that is invoked on state changes.
  MOCK_METHOD2(OnStateChange, void(State, State));

  // Callbacks that will be invoked by the appropriate hooks in the base class.
  MOCK_METHOD0(StartedCallback, bool());
  MOCK_METHOD0(InterruptedCallback, bool());
  MOCK_METHOD0(StoppedCallback, bool());

  // Used to simulate a startup sequence.
  bool InitFailsStartup() {
    return false;
  }
  bool InitSucceedsStartup() {
    OnInitialized();
    return false;
  }
  bool SuccessfulStartup() {
    OnInitialized();
    OnStarted();
    return true;
  }

  // Used to simulate a successful stop.
  bool SuccessfulStop() {
    OnStopped();
    return true;
  }

  // Exposed for testing.
  using Service::OnInterrupted;

 private:
  // @{
  // We use these to register callbacks with our base class, and plumb them
  // into the mocked methods above.

  static bool InvokeStartedCallback(Service* service) {
    DCHECK(service != NULL);
    TestService* test_service = static_cast<TestService*>(service);
    return test_service->StartedCallback();
  }

  static bool InvokeInterruptedCallback(Service* service) {
    DCHECK(service != NULL);
    TestService* test_service = static_cast<TestService*>(service);
    return test_service->InterruptedCallback();
  }

  static bool InvokeStoppedCallback(Service* service) {
    DCHECK(service != NULL);
    TestService* test_service = static_cast<TestService*>(service);
    return test_service->StoppedCallback();
  }
  // @}
};
typedef testing::StrictMock<TestService> StrictTestService;

}  // namespace

TEST(ServiceTest, MutatorsAndAccessors) {
  StrictTestService t;
  EXPECT_EQ(kTestServiceName, t.name());
  EXPECT_TRUE(t.instance_id().empty());
  EXPECT_EQ(Service::kUnused, t.state());

  std::wstring instance_id = L"Foobar";
  t.set_instance_id(instance_id);
  EXPECT_EQ(instance_id, t.instance_id());

  t.SetCallbacks();
}

TEST(ServiceTest, FailedInit) {
  StrictTestService t;
  t.SetCallbacks();

  EXPECT_EQ(Service::kUnused, t.state());
  EXPECT_CALL(t, StartImpl()).Times(1).
      WillOnce(Invoke(&t, &TestService::InitFailsStartup));
  EXPECT_CALL(t, OnStateChange(Service::kUnused, Service::kErrored));
  EXPECT_FALSE(t.Start());
  EXPECT_EQ(Service::kErrored, t.state());
}

TEST(ServiceTest, SuccessfulInitFailedStartup) {
  StrictTestService t;
  t.SetCallbacks();

  EXPECT_EQ(Service::kUnused, t.state());
  EXPECT_CALL(t, StartImpl()).Times(1).
      WillOnce(Invoke(&t, &TestService::InitSucceedsStartup));
  EXPECT_CALL(t, OnStateChange(Service::kUnused, Service::kInitialized));
  EXPECT_CALL(t, OnStateChange(Service::kInitialized, Service::kErrored));
  EXPECT_FALSE(t.Start());
  EXPECT_EQ(Service::kErrored, t.state());
}

TEST(ServiceTest, SuccessfulStartupFailedStop) {
  StrictTestService t;
  t.SetCallbacks();

  EXPECT_EQ(Service::kUnused, t.state());
  EXPECT_CALL(t, StartImpl()).Times(1).
      WillOnce(Invoke(&t, &TestService::SuccessfulStartup));
  EXPECT_CALL(t, StartedCallback()).Times(1).WillOnce(Return(true));
  EXPECT_CALL(t, OnStateChange(Service::kUnused, Service::kInitialized));
  EXPECT_CALL(t, OnStateChange(Service::kInitialized, Service::kRunning));
  EXPECT_TRUE(t.Start());
  EXPECT_EQ(Service::kRunning, t.state());

  EXPECT_CALL(t, StopImpl()).Times(1).WillOnce(Return(false));
  EXPECT_CALL(t, OnStateChange(Service::kRunning, Service::kStopping));
  EXPECT_CALL(t, OnStateChange(Service::kStopping, Service::kErrored));
  EXPECT_FALSE(t.Stop());
  EXPECT_EQ(Service::kErrored, t.state());
}

TEST(ServiceTest, SuccessfulStartupSuccessfulStop) {
  StrictTestService t;
  t.SetCallbacks();

  EXPECT_EQ(Service::kUnused, t.state());
  EXPECT_CALL(t, StartImpl()).Times(1).
      WillOnce(Invoke(&t, &TestService::SuccessfulStartup));
  EXPECT_CALL(t, StartedCallback()).Times(1).WillOnce(Return(true));
  EXPECT_CALL(t, OnStateChange(Service::kUnused, Service::kInitialized));
  EXPECT_CALL(t, OnStateChange(Service::kInitialized, Service::kRunning));
  EXPECT_TRUE(t.Start());
  EXPECT_EQ(Service::kRunning, t.state());

  EXPECT_CALL(t, StopImpl()).Times(1).
      WillOnce(Invoke(&t, &TestService::SuccessfulStop));
  EXPECT_CALL(t, StoppedCallback()).Times(1).WillOnce(Return(true));
  EXPECT_CALL(t, OnStateChange(Service::kRunning, Service::kStopping));
  EXPECT_CALL(t, OnStateChange(Service::kStopping, Service::kStopped));
  EXPECT_TRUE(t.Stop());
  EXPECT_EQ(Service::kStopped, t.state());
}

TEST(ServiceTest, InterruptCallbackWorks) {
  StrictTestService t;
  t.SetCallbacks();

  EXPECT_CALL(t, InterruptedCallback());
  t.OnInterrupted();
}

}  // namespace common
}  // namespace trace
