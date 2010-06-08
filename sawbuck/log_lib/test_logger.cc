// Copyright 2009 Google Inc.
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
// Test logger implementation.
#include "base/event_trace_provider_win.h"
#include <cguid.h>
#include <initguid.h>

// We make like Chrome for the purposes of this test.
DEFINE_GUID(kChromeTraceProviderName,
    0x7fe69228, 0x633e, 0x4f06, 0x80, 0xc1, 0x52, 0x7f, 0xea, 0x23, 0xe3, 0xa7);

DEFINE_GUID(kLogEventId,
    0x7fe69228, 0x633e, 0x4f06, 0x80, 0xc1, 0x52, 0x7f, 0xea, 0x23, 0xe3, 0xa7);

enum LogMessageTypes {
  // A textual only log message, contains a zero-terminated string.
  LOG_MESSAGE = 10,
  // A message with a stack trace, followed by the zero-terminated
  // message text.
  LOG_MESSAGE_WITH_STACKTRACE = 11,
};

int main(int argc, char **argv) {
  EtwTraceProvider provider(kChromeTraceProviderName);
  provider.Register();

  for (int i = 1; i < argc; ++i) {
    EtwMofEvent<3> event(kLogEventId,
                         LOG_MESSAGE_WITH_STACKTRACE,
                         TRACE_LEVEL_ERROR);
    void* stack_trace[32];
    const DWORD depth = ::CaptureStackBackTrace(0,
                                                arraysize(stack_trace),
                                                stack_trace,
                                                NULL);
    event.SetField(0, sizeof(depth), &depth);
    event.SetField(1, sizeof(stack_trace[0]) * depth, &stack_trace);
    DWORD len = strlen(argv[i]);
    event.SetField(2, len, argv[i]);
    provider.Log(event.get());
  }
}
