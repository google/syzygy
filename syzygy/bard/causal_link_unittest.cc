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

#include "syzygy/bard/causal_link.h"

#include "base/memory/scoped_ptr.h"
#include "base/threading/simple_thread.h"
#include "gtest/gtest.h"

namespace bard {

namespace {

// Main Runner, used to test both normal Waits and TimedWaits.
class WaitRunner : public base::DelegateSimpleThread::Delegate {
 public:
  explicit WaitRunner(CausalLink* causal_link)
      : causal_link_(causal_link),
        run_ended_(false),
        time_(base::TimeDelta::Max()),
        timed_wait_signaled_(false) {}

  void Run() override {
    if (time_ != base::TimeDelta::Max()) {
      timed_wait_signaled_ = causal_link_->TimedWait(time_);
    } else {
      causal_link_->Wait();
    }
    run_ended_ = true;
  }

  bool run_ended() const { return run_ended_; }
  void set_time(const base::TimeDelta& time) { time_ = time; }
  bool timed_wait_signaled() const { return timed_wait_signaled_; }

 protected:
  CausalLink* causal_link_;
  base::TimeDelta time_;

  bool run_ended_;
  bool timed_wait_signaled_;
};

// Delegate Runner to Signal links.
// Used as a helper to signal links and then be sure that the signal
// call ended before doing anything else.
class SignalRunner : public base::DelegateSimpleThread::Delegate {
 public:
  explicit SignalRunner(CausalLink* causal_link) : causal_link_(causal_link) {}

  void Run() override { causal_link_->Signal(); }

 protected:
  CausalLink* causal_link_;
};

class CausalLinkTest : public testing::Test {
 public:
  CausalLinkTest() : signaler_(&link_), waiter_(&link_) {}

 protected:
  CausalLink link_;

  SignalRunner signaler_;
  WaitRunner waiter_;
};

}  // namespace

TEST_F(CausalLinkTest, TestWait) {
  // Tells the link to wait, and the link blocks the thread.
  // Then signals the link, which stops blocking the thread.
  base::DelegateSimpleThread signaler_thread(&signaler_, "Signal Thread");
  base::DelegateSimpleThread waiter_thread(&waiter_, "Waiter Thread");

  waiter_thread.Start();
  EXPECT_FALSE(waiter_.run_ended());
  signaler_thread.Start();
  signaler_thread.Join();
  EXPECT_TRUE(waiter_.run_ended());
  waiter_thread.Join();
}

TEST_F(CausalLinkTest, TestSignaledLink) {
  // Signals the link and tells it to wait, but since the link is
  // already signaled, the link doesn't block the thread at all.
  base::DelegateSimpleThread signaler_thread(&signaler_, "Signal Thread");
  base::DelegateSimpleThread waiter_thread(&waiter_, "Waiter Thread");

  signaler_thread.Start();
  signaler_thread.Join();

  // Signaled link doesn't block the thread.
  EXPECT_FALSE(waiter_.run_ended());
  waiter_thread.Start();
  EXPECT_TRUE(waiter_.run_ended());
  waiter_thread.Join();
}

TEST_F(CausalLinkTest, TestLinkReset) {
  // Signals and reset the link and then tells it to wait, thus
  // it successfully blocks the thread.
  base::DelegateSimpleThread signaler_thread(&signaler_, "Signal Thread");
  base::DelegateSimpleThread signaler_thread_2(&signaler_, "Signal Thread");
  base::DelegateSimpleThread waiter_thread(&waiter_, "Waiter Thread");

  signaler_thread.Start();
  signaler_thread.Join();

  // Link reset.
  link_.Reset();

  // Since link is reset, it blocks the thread once again.
  waiter_thread.Start();
  EXPECT_FALSE(waiter_.run_ended());
  signaler_thread_2.Start();
  signaler_thread_2.Join();
  waiter_thread.Join();
  EXPECT_TRUE(waiter_.run_ended());
}

TEST_F(CausalLinkTest, TestTimedWaitTimeout) {
  // Timeout test. Since link doesn't need to be signaled after a TimedWait
  // call, the thread is eventually unblocked.
  const base::TimeDelta kOneSecond = base::TimeDelta::FromSeconds(1);

  waiter_.set_time(kOneSecond);

  base::DelegateSimpleThread waiter_thread(&waiter_, "Waiter Thread");

  waiter_thread.Start();
  EXPECT_FALSE(waiter_.run_ended());
  // Waits for the thread to be unblocked and finish running.
  waiter_thread.Join();
  EXPECT_TRUE(waiter_.run_ended());
  // Checks that the link indicates that it has not been signaled.
  EXPECT_FALSE(waiter_.timed_wait_signaled());
}

TEST_F(CausalLinkTest, TestTimedWaitSignalBreak) {
  // Thread is blocked through a TimedWait but the link is signaled anyway and
  // thus thread is unblocked before the time expires.
  const base::TimeDelta kOneHour = base::TimeDelta::FromHours(1);

  waiter_.set_time(kOneHour);

  base::DelegateSimpleThread signaler_thread(&signaler_, "Signal Thread");
  base::DelegateSimpleThread waiter_thread(&waiter_, "Waiter Thread");

  waiter_thread.Start();
  EXPECT_FALSE(waiter_.run_ended());
  // Signal the link and makes sure that the signal completed.
  signaler_thread.Start();
  signaler_thread.Join();
  // Checks if thread was unblocked after the link was signaled.
  EXPECT_TRUE(waiter_.run_ended());
  // Checks that the link indicates that it has been signaled.
  EXPECT_TRUE(waiter_.timed_wait_signaled());
  waiter_thread.Join();
}

}  // namespace bard
