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
// Call trace event parsing classes.

#ifndef SYZYGY_CALL_TRACE_PARSER_H_
#define SYZYGY_CALL_TRACE_PARSER_H_

#include "base/time.h"
#include "base/file_path.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/call_trace_parser.h"

namespace call_trace {
namespace parser {

class Parser : public CallTraceParser {
 public:
  explicit Parser(CallTraceEvents* event_handler) {
    set_call_trace_event_sink(event_handler);
  }

  bool Parse(const FilePath& trace_file_path);

 private:
  bool ParseSegmentEvents(const TraceFileHeader& file_header,
                          const TraceFileSegment::Header& segment_header,
                          uint8* buffer,
                          size_t buffer_length);

};

}  // namespace call_trace::parser
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_PARSER_H_
