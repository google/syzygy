// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/service_bridge.h"

#include <Windows.h>  // NOLINT
#include <Rpc.h>

#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "gtest/gtest.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/kasko_rpc.h"
#include "syzygy/kasko/service.h"
#include "syzygy/kasko/testing/mock_service.h"

namespace kasko {

namespace {

const base::char16* const kValidRpcProtocol = L"ncalrpc";
const base::char16* const kTestRpcEndpointPrefix = L"syzygy-kasko-test-svc";

base::string16 GetTestEndpoint() {
  return kTestRpcEndpointPrefix + base::UintToString16(::GetCurrentProcessId());
}

class BlockingService : public Service {
 public:
  BlockingService(base::WaitableEvent* release_call,
                  base::WaitableEvent* blocking);
  virtual ~BlockingService();

  // Service implementation
  virtual void SendDiagnosticReport(
      base::ProcessId client_process_id,
      base::PlatformThreadId thread_id,
      const MinidumpRequest& request) override;

 private:
  base::WaitableEvent* release_call_;
  base::WaitableEvent* blocking_;
  DISALLOW_COPY_AND_ASSIGN(BlockingService);
};

BlockingService::BlockingService(base::WaitableEvent* release_call,
                                 base::WaitableEvent* blocking)
    : release_call_(release_call), blocking_(blocking) {}

BlockingService::~BlockingService() {}

void BlockingService::SendDiagnosticReport(
    base::ProcessId client_process_id,
    base::PlatformThreadId thread_id,
    const MinidumpRequest& request) {
  blocking_->Signal();
  release_call_->Wait();
}

void InvokeAndCheckRpcStatus(const base::Callback<RPC_STATUS(void)>& callback) {
  ASSERT_EQ(RPC_S_OK, callback.Run());
}

base::Closure WrapRpcStatusCallback(
    const base::Callback<RPC_STATUS(void)>& callback) {
  return base::Bind(InvokeAndCheckRpcStatus, callback);
}

void DoInvokeService(const base::string16& protocol,
                     const base::string16& endpoint,
                     const std::string& protobuf,
                     bool* complete,
                     size_t crash_keys_length,
                     const CrashKey* crash_keys) {
  common::rpc::ScopedRpcBinding rpc_binding;
  ASSERT_TRUE(rpc_binding.Open(protocol, endpoint));

  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(), NULL, 0, SMALL_DUMP,
      protobuf.length(), reinterpret_cast<const signed char*>(protobuf.c_str()),
      crash_keys_length, crash_keys);
  ASSERT_FALSE(status.exception_occurred);
  ASSERT_TRUE(status.succeeded());
  *complete = true;
}

}  // namespace

TEST(KaskoServiceBridgeTest, ConstructDestruct) {
  std::vector<testing::MockService::CallRecord> call_log;
  {
    ServiceBridge instance(
        L"aaa", L"bbb",
        scoped_ptr<Service>(new testing::MockService(&call_log)));
  }
  {
    ServiceBridge instance(
        L"aaa", L"bbb",
        scoped_ptr<Service>(new testing::MockService(&call_log)));
  }
}

TEST(KaskoServiceBridgeTest, StopNonRunningInstance) {
  std::vector<testing::MockService::CallRecord> call_log;
  ServiceBridge instance(
      L"aaa", L"bbb", scoped_ptr<Service>(new testing::MockService(&call_log)));
  instance.Stop();
}

TEST(KaskoServiceBridgeTest, FailToRunWithBadProtocol) {
  std::vector<testing::MockService::CallRecord> call_log;
  {
    ServiceBridge instance(
        L"aaa", GetTestEndpoint(),
        scoped_ptr<Service>(new testing::MockService(&call_log)));
    ASSERT_FALSE(instance.Run());
    // Stop should not crash in this case.
    instance.Stop();
  }
}

TEST(KaskoServiceBridgeTest, RunSuccessfully) {
  std::vector<testing::MockService::CallRecord> call_log;

  {
    ServiceBridge instance(
        kValidRpcProtocol, GetTestEndpoint(),
        scoped_ptr<Service>(new testing::MockService(&call_log)));
    ASSERT_TRUE(instance.Run());
    instance.Stop();

    // Second run, same instance.
    ASSERT_TRUE(instance.Run());
    instance.Stop();
  }
  {
    // Second instance.
    ServiceBridge instance(
        kValidRpcProtocol, GetTestEndpoint(),
        scoped_ptr<Service>(new testing::MockService(&call_log)));
    ASSERT_TRUE(instance.Run());
    instance.Stop();
  }
}

TEST(KaskoServiceBridgeTest, InvokeService) {
  std::vector<testing::MockService::CallRecord> call_log;

  base::string16 protocol = kValidRpcProtocol;
  base::string16 endpoint = GetTestEndpoint();
  ServiceBridge instance(
      protocol, endpoint,
      scoped_ptr<Service>(new testing::MockService(&call_log)));
  ASSERT_TRUE(instance.Run());

  base::ScopedClosureRunner stop_service_bridge(
      base::Bind(&ServiceBridge::Stop, base::Unretained(&instance)));

  std::string protobuf = "hello world";
  bool complete = false;
  CrashKey crash_keys[] = {{reinterpret_cast<const wchar_t*>(L"foo"),
                            reinterpret_cast<const wchar_t*>(L"bar")},
                           {reinterpret_cast<const wchar_t*>(L"hello"),
                            reinterpret_cast<const wchar_t*>(L"world")}};

  DoInvokeService(protocol, endpoint, protobuf, &complete,
                  arraysize(crash_keys), crash_keys);
  ASSERT_TRUE(complete);
  ASSERT_EQ(1u, call_log.size());
  ASSERT_EQ(::GetCurrentProcessId(), call_log[0].client_process_id);
  ASSERT_EQ(protobuf, call_log[0].protobuf);
  ASSERT_EQ(2u, call_log[0].crash_keys.size());
  auto entry = call_log[0].crash_keys.find(L"foo");
  ASSERT_NE(call_log[0].crash_keys.end(), entry);
  ASSERT_EQ(L"bar", entry->second);
  entry = call_log[0].crash_keys.find(L"hello");
  ASSERT_NE(call_log[0].crash_keys.end(), entry);
  ASSERT_EQ(L"world", entry->second);
}


TEST(KaskoServiceBridgeTest, StopBlocksUntilCallsComplete) {
  base::WaitableEvent release_call(false, false);
  base::WaitableEvent blocking(false, false);

  base::string16 protocol = kValidRpcProtocol;
  base::string16 endpoint = GetTestEndpoint();
  ServiceBridge instance(
      protocol, endpoint,
      scoped_ptr<Service>(new BlockingService(&release_call, &blocking)));
  ASSERT_TRUE(instance.Run());

  base::ScopedClosureRunner stop_service_bridge(
      base::Bind(&ServiceBridge::Stop, base::Unretained(&instance)));
  // In case an assertion fails, make sure that we will not block.
  base::ScopedClosureRunner signal_release_call(base::Bind(
      &base::WaitableEvent::Signal, base::Unretained(&release_call)));

  std::string protobuf = "hello world";
  bool complete = false;
  CrashKey crash_keys[] = {{reinterpret_cast<const wchar_t*>(L"foo"),
                            reinterpret_cast<const wchar_t*>(L"bar")},
                           {reinterpret_cast<const wchar_t*>(L"hello"),
                            reinterpret_cast<const wchar_t*>(L"world")}};

  base::Thread client_thread("client thread");
  ASSERT_TRUE(client_thread.Start());
  client_thread.message_loop()->PostTask(
      FROM_HERE,
      base::Bind(&DoInvokeService, protocol, endpoint, protobuf,
                 base::Unretained(&complete), arraysize(crash_keys),
                 base::Unretained(crash_keys)));
  // In case the DoInvokeService fails, let's make sure we unblock ourselves.
  client_thread.message_loop()->PostTask(
      FROM_HERE,
      base::Bind(&base::WaitableEvent::Signal, base::Unretained(&blocking)));
  blocking.Wait();

  // Either DoInvokeService failed (complete == true), or we are blocking in
  // BlockingService::SendDiagnosticReport (complete == false).
  ASSERT_FALSE(complete);

  // Reduce the chance of false positives by giving the service call a chance to
  // complete. (It shouldn't.)
  ::Sleep(100);

  base::Thread stop_thread("stop thread");
  ASSERT_TRUE(stop_thread.Start());
  stop_thread.message_loop()->PostTask(
      FROM_HERE, base::Bind(&ServiceBridge::Stop, base::Unretained(&instance)));
  ASSERT_FALSE(complete);

  // Stop is waiting for the pending call to complete. Let's unblock it now.
  release_call.Signal();

  // This will not return until the ServiceBridge::Stop has completed.
  stop_thread.Stop();
  ASSERT_TRUE(complete);
}

}  // namespace kasko
