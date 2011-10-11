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
// Implementation of call trace log parsing.

#include "syzygy/call_trace/parser.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "sawbuck/common/buffer_parser.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"

namespace call_trace {
namespace parser {

bool Parser::Parse(const FilePath& trace_file_path) {
  DCHECK(!trace_file_path.empty());

  file_util::ScopedFILE trace_file(file_util::OpenFile(trace_file_path, "rb"));
  if (!trace_file.get()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Unable to open '" << trace_file_path.value() << "' "
        << com::LogWe(error) << ".";
    return false;
  }

  // Let's reserve some space for the variable length header
  enum { kReasonablePageSize = 4096 };
  uint8 raw_buffer[kReasonablePageSize];
  ZeroMemory(&raw_buffer, sizeof(raw_buffer));

  // Populate the buffer
  size_t bytes_read = ::fread(&raw_buffer, 1, sizeof(raw_buffer),
                              trace_file.get());
  if (bytes_read < sizeof(TraceFileHeader)) {
    LOG(ERROR) << "Failed to read trace file header.";
    return false;
  }

  // Create a typed alias to the raw buffer.
  TraceFileHeader& file_header =
      *reinterpret_cast<TraceFileHeader*>(&raw_buffer[0]);
  size_t next_segment = file_header.block_size;
  scoped_ptr_malloc<uint8> buffer;
  size_t buffer_size = 0;
  while (true) {
    if (::fseek(trace_file.get(), next_segment, SEEK_SET) != 0) {
      LOG(ERROR) << "Failed to seek segment boundary " << next_segment << ".";
      return false;
    }

    RecordPrefix segment_prefix;
    if (::fread(&segment_prefix, sizeof(segment_prefix), 1,
                trace_file.get()) !=  1) {
      if (::feof(trace_file.get()))
        break;

      LOG(ERROR) << "Failed to read segment header prefix.";
      return false;
    }

    if (segment_prefix.type != TraceFileSegment::Header::kTypeId ||
        segment_prefix.size != sizeof(TraceFileSegment::Header) ||
        segment_prefix.version.hi != TRACE_VERSION_HI ||
        segment_prefix.version.lo != TRACE_VERSION_LO) {
      LOG(ERROR) << "Unrecognized record prefix for segment header.";
      return false;
    }

    TraceFileSegment::Header segment_header;
    if (::fread(&segment_header, sizeof(segment_header), 1,
                trace_file.get()) !=  1) {
      LOG(ERROR) << "Failed to read segment header.";
      return false;
    }

    size_t aligned_size = common::AlignUp(segment_header.segment_length,
                                          file_header.block_size);

    if (aligned_size > buffer_size) {
      buffer.reset(reinterpret_cast<uint8*>(::malloc(aligned_size)));
      buffer_size = aligned_size;
    }

    if (::fread(buffer.get(), segment_header.segment_length, 1,
                trace_file.get()) !=  1) {
      LOG(ERROR) << "Failed to read segment.";
      return false;
    }

    if (!ParseSegmentEvents(file_header, segment_header, buffer.get(),
                            segment_header.segment_length)) {
      return false;
    }

    next_segment = common::AlignUp(
        next_segment + sizeof(segment_prefix) + sizeof(segment_header) +
            segment_header.segment_length,
        file_header.block_size);
  }

  return true;
}

bool Parser::ParseSegmentEvents(const TraceFileHeader& file_header,
                                const TraceFileSegment::Header& segment_header,
                                uint8* buffer,
                                size_t buffer_length) {
  DCHECK(buffer != NULL);

  EVENT_TRACE event_record = {};

  event_record.Header.ProcessId = file_header.process_id;
  event_record.Header.ThreadId = segment_header.thread_id;
  event_record.Header.Guid = kCallTraceEventClass;

  uint8* read_ptr = buffer;
  uint8* end_ptr = read_ptr + buffer_length;

  while (read_ptr < end_ptr) {
    RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(read_ptr);
    read_ptr += sizeof(RecordPrefix) + prefix->size;
    if (read_ptr > end_ptr) {
      LOG(ERROR) << "Reading off end of segment buffer.";
      return false;
    }

    event_record.Header.Class.Type = prefix->type;
    event_record.Header.TimeStamp.QuadPart = prefix->timestamp;
    event_record.MofData = prefix + 1;
    event_record.MofLength = prefix->size;
    if (!ProcessOneEvent(&event_record)) {
      LOG(ERROR) << "Failed to process event of type " << prefix->type << ".";
      return false;
    }
  }

  return true;
}

}  // namespace call_trace::parser
}  // namespace call_trace
