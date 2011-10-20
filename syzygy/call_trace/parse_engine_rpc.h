// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_CALL_TRACE_PARSE_ENGINE_RPC_H_
#define SYZYGY_CALL_TRACE_PARSE_ENGINE_RPC_H_

#include "base/time.h"
#include "base/file_path.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/parse_engine.h"

namespace call_trace {
namespace parser {

class ParseEngineRpc : public ParseEngine {
 public:
  ParseEngineRpc();
  virtual ~ParseEngineRpc();

  // Returns true if the file given by @p trace_file_path is parseable by this
  // parse engine.
  virtual bool IsRecognizedTraceFile(const FilePath& trace_file_path) OVERRIDE;

  // Opens the trace log given by @p trace_file_path and prepares it for
  // consumption. It is an error to call this method given a file that
  // will not be recognized by the parse engine.
  virtual bool OpenTraceFile(const FilePath& trace_file_path) OVERRIDE;

  // Consume all events across all currently open trace files and for each
  // event call the dispatcher to notify the event handler.
  virtual bool ConsumeAllEvents() OVERRIDE;

  // Close all currently open trace files.
  virtual bool CloseAllTraceFiles() OVERRIDE;

 private:
  typedef std::vector<FilePath> TraceFileSet;
  typedef TraceFileSet::iterator TraceFileIter;

  bool ConsumeTraceFile(const FilePath& trace_file_path);

  bool ConsumeSegmentEvents(const TraceFileHeader& file_header,
                            const TraceFileSegment::Header& segment_header,
                            uint8* buffer,
                            size_t buffer_length);

  TraceFileSet trace_file_set_;

  DISALLOW_COPY_AND_ASSIGN(ParseEngineRpc);
};

}  // namespace call_trace::parser
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_PARSE_ENGINE_RPC_H_
