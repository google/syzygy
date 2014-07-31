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
#include "sawbuck/log_lib/log_consumer.h"

#include <cguid.h>
#include "base/logging_win.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <initguid.h>  // NOLINT - must be last.

namespace {

// {2E79E967-BB99-4c42-B888-792EED6CEB98}
DEFINE_GUID(kRandomGuid,
    0x2e79e967, 0xbb99,
        0x4c42, 0xb8, 0x88, 0x79, 0x2e, 0xed, 0x6c, 0xeb, 0x98);

using testing::_;
using testing::AllOf;
using testing::ElementsAreArray;
using testing::Field;
using testing::IsNull;
using testing::NotNull;
using testing::StrictMock;
using testing::StrEq;

class MockLogEvents: public LogEvents {
 public:
  MOCK_METHOD1(OnLogMessage, void(const LogEvents::LogMessage& msg));
};

class EventTrace: public EVENT_TRACE {
 public:
  EventTrace(const GUID& provider_name, UCHAR type, UCHAR level,
      DWORD process_id, DWORD thread_id, const base::Time& time,
      size_t data_len, void* data) {
    memset(this, 0, sizeof(*this));

    Header.Size = sizeof(*this);
    Header.Class.Type = type;
    Header.Class.Level = level;
    Header.Class.Version = 0; // Always 0 for now
    Header.ThreadId = thread_id;
    Header.ProcessId = process_id;
    reinterpret_cast<FILETIME&>(Header.TimeStamp) = time.ToFileTime();
    Header.Guid = provider_name;
    InstanceId = 0;
    ParentInstanceId = 0;
    ParentGuid = GUID_NULL;
    MofData = data;
    MofLength = data_len;
  }
};

char kMsgText[] = "Nothing to see here, please move on";

class LogParserTest: public testing::Test {
 public:
  LogParserTest() : log_msg_(logging::kLogEventId, logging::LOG_MESSAGE,
      TRACE_LEVEL_INFORMATION, ::GetCurrentProcessId(), ::GetCurrentThreadId(),
      base::Time::Now(), sizeof(kMsgText), kMsgText) {
  }

  virtual void SetUp() {
    parser_.set_event_sink(&events_);
  }

 protected:
  EventTrace log_msg_;
  StrictMock<MockLogEvents> events_;
  LogParser parser_;
};

TEST_F(LogParserTest, ParseOtherEventClass) {
  // Change the event class.
  log_msg_.Header.Guid = kRandomGuid;

  EXPECT_FALSE(parser_.ProcessOneEvent(&log_msg_));
}

TEST_F(LogParserTest, ParseOtherEventType) {
  // Change the event type.
  log_msg_.Header.Class.Type = 109;

  EXPECT_FALSE(parser_.ProcessOneEvent(&log_msg_));
}

TEST_F(LogParserTest, ParseOtherEventVersion) {
  // Change the event version.
  log_msg_.Header.Class.Version = 3;

  EXPECT_FALSE(parser_.ProcessOneEvent(&log_msg_));
}

TEST_F(LogParserTest, ParseLogEvent) {
  typedef LogEvents::LogMessage Msg;
  EXPECT_CALL(events_, OnLogMessage(AllOf(
      AllOf(
          Field(&Msg::level, TRACE_LEVEL_INFORMATION),
          Field(&Msg::process_id, ::GetCurrentProcessId()),
          Field(&Msg::thread_id, ::GetCurrentThreadId())),
      AllOf(
          Field(&Msg::trace_depth, 0),
          Field(&Msg::traces, IsNull()),
          Field(&Msg::message_len, strlen(kMsgText)),
          Field(&Msg::message, StrEq(kMsgText))))))
              .Times(1);

  EXPECT_TRUE(parser_.ProcessOneEvent(&log_msg_));
}

TEST_F(LogParserTest, ParseLogEventWithStackTrace) {
  void* backtrace[32];
  int depth = ::CaptureStackBackTrace(0,
                                      arraysize(backtrace),
                                      backtrace,
                                      NULL);

  char buffer[sizeof(DWORD) + sizeof(backtrace) + sizeof(kMsgText)];
  char* ptr = buffer;

  // Construct the concatenation of:
  // - The stack trace depth.
  // - The stack trace.
  // - The log message.
  *reinterpret_cast<DWORD*>(ptr) = depth;
  ptr += sizeof(DWORD);
  memcpy(ptr, backtrace, depth * sizeof(backtrace[0]));
  ptr += depth * sizeof(backtrace[0]);
  memcpy(ptr, kMsgText, sizeof(kMsgText));
  ptr += sizeof(kMsgText);

  log_msg_.Header.Class.Type = logging::LOG_MESSAGE_WITH_STACKTRACE;
  log_msg_.MofData = buffer;
  log_msg_.MofLength = ptr - buffer;

  // Now set up the expectation.
  typedef LogEvents::LogMessage Msg;
  EXPECT_CALL(events_, OnLogMessage(AllOf(
      AllOf(
          Field(&Msg::level, TRACE_LEVEL_INFORMATION),
          Field(&Msg::process_id, ::GetCurrentProcessId()),
          Field(&Msg::thread_id, ::GetCurrentThreadId())),
      AllOf(
          Field(&Msg::trace_depth, depth),
          Field(&Msg::traces, NotNull()),
          Field(&Msg::message_len, strlen(kMsgText)),
          Field(&Msg::message, StrEq(kMsgText))))))
      .Times(1);

  EXPECT_TRUE(parser_.ProcessOneEvent(&log_msg_));
}

}  // namespace
