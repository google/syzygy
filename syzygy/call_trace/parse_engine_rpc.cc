// Copyright 2012 Google Inc.
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
// Implementation of RPC call-trace parsing.

#include "syzygy/call_trace/parse_engine_rpc.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "sawbuck/common/buffer_parser.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"

using common::AlignUp;

namespace call_trace {
namespace parser {

ParseEngineRpc::ParseEngineRpc() : ParseEngine("RPC", true) {
}

ParseEngineRpc::~ParseEngineRpc() {
}

bool ParseEngineRpc::IsRecognizedTraceFile(const FilePath& trace_file_path) {
  file_util::ScopedFILE trace_file(file_util::OpenFile(trace_file_path, "rb"));
  if (!trace_file.get()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Unable to open '" << trace_file_path.value() << "': "
               << com::LogWe(error) << ".";
    return false;
  }

  TraceFileHeader::Signature signature = {};
  size_t bytes_read = ::fread(&signature,
                              1,
                              sizeof(signature),
                              trace_file.get());
  if (bytes_read < sizeof(signature)) {
    LOG(ERROR) << "Failed to read trace file signature.";
    return false;
  }

  return 0 == ::memcmp(&signature,
                       &TraceFileHeader::kSignatureValue,
                       sizeof(signature));
}

bool ParseEngineRpc::OpenTraceFile(const FilePath& trace_file_path) {
  trace_file_set_.push_back(trace_file_path);
  return true;
}

bool ParseEngineRpc::CloseAllTraceFiles() {
  trace_file_set_.clear();
  return true;
}

bool ParseEngineRpc::ConsumeAllEvents() {
  TraceFileIter it = trace_file_set_.begin();
  for (; it != trace_file_set_.end(); ++it) {
    if (!ConsumeTraceFile(*it)) {
      LOG(ERROR) << "Failed to consume '" << it->value() << "'.";
      return false;
    }
  }

  return true;
}

bool ParseEngineRpc::ConsumeTraceFile(const FilePath& trace_file_path) {
  DCHECK(!trace_file_path.empty());

  LOG(INFO) << "Processing '" << trace_file_path.BaseName().value() << "'.";

  file_util::ScopedFILE trace_file(file_util::OpenFile(trace_file_path, "rb"));
  if (!trace_file.get()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Unable to open '" << trace_file_path.value() << "': "
               << com::LogWe(error) << ".";
    return false;
  }

  // Let's reserve some space for the variable length header.
  const size_t kReasonableHeaderSize = 4096;
  std::vector<uint8> raw_buffer;
  raw_buffer.reserve(kReasonableHeaderSize);
  raw_buffer.resize(sizeof(TraceFileHeader));

  // Populate the buffer.
  DCHECK_EQ(raw_buffer.size(), sizeof(TraceFileHeader));
  size_t bytes_read = ::fread(&raw_buffer[0],
                              1,
                              raw_buffer.size(),
                              trace_file.get());
  if (bytes_read != raw_buffer.size()) {
    LOG(ERROR) << "Failed to read trace file header.";
    return false;
  }

  // Create a typed alias to the raw buffer.
  const TraceFileHeader* file_header =
      reinterpret_cast<const TraceFileHeader*>(&raw_buffer[0]);

  // Validate the header size, which is the size of the static header structure
  // plus the length (in bytes) of the wide-char command-line.
  size_t expected_header_size = sizeof(TraceFileHeader) +
                                sizeof(wchar_t) * file_header->command_line_len;
  if (file_header->header_size != expected_header_size) {
    LOG(ERROR) << "Invalid trace file header.";
    return false;
  }

  // Make sure there's enough room for the variable length part of the header
  // and then append read the rest of the header. Note that the underlying raw
  // buffer might move when it is resized.
  size_t bytes_to_read = file_header->header_size - raw_buffer.size();
  raw_buffer.resize(file_header->header_size);
  file_header = reinterpret_cast<const TraceFileHeader*>(&raw_buffer[0]);
  bytes_read = ::fread(&raw_buffer[sizeof(TraceFileHeader)],
                       1,
                       bytes_to_read,
                       trace_file.get());
  if (bytes_read != bytes_to_read) {
    LOG(ERROR) << "Failed to read trace file header.";
    return false;
  }

  // Check the file signature.
  if (0 != memcmp(&file_header->signature,
                  &TraceFileHeader::kSignatureValue,
                  sizeof(file_header->signature))) {
    LOG(ERROR) << "Not a valid RPC call-trace file.";
    return false;
  }

  // Add the executable's module information to the process map. This is in
  // case the executable itself is instrumented, so that trace events will map
  // to a module in the process map.
  ModuleInformation module_info = {};
  module_info.base_address = file_header->module_base_address;
  module_info.image_file_name = file_header->module_path;
  module_info.module_size = file_header->module_size;
  module_info.image_checksum = file_header->module_checksum;
  module_info.time_date_stamp = file_header->module_time_date_stamp;
  AddModuleInformation(file_header->process_id, module_info);

  // Notify the event handler that a process has started.
  LARGE_INTEGER big_timestamp = {};
  big_timestamp.QuadPart = file_header->timestamp;
  base::Time start_time(base::Time::FromFileTime(
      *reinterpret_cast<FILETIME*>(&big_timestamp)));
  event_handler_->OnProcessStarted(start_time, file_header->process_id);

  // Consume the body of the trace file.
  size_t next_segment = AlignUp(file_header->header_size,
                                file_header->block_size);
  scoped_ptr_malloc<uint8> buffer;
  size_t buffer_size = 0;
  while (true) {
    if (::fseek(trace_file.get(), next_segment, SEEK_SET) != 0) {
      LOG(ERROR) << "Failed to seek segment boundary " << next_segment << ".";
      return false;
    }

    RecordPrefix segment_prefix;
    if (::fread(&segment_prefix,
                sizeof(segment_prefix),
                1,
                trace_file.get()) !=  1) {
      if (::feof(trace_file.get()))
        break;

      LOG(ERROR) << "Failed to read segment header prefix.";
      return false;
    }

    if (segment_prefix.type != TraceFileSegmentHeader::kTypeId ||
        segment_prefix.size != sizeof(TraceFileSegmentHeader) ||
        segment_prefix.version.hi != TRACE_VERSION_HI ||
        segment_prefix.version.lo != TRACE_VERSION_LO) {
      LOG(ERROR) << "Unrecognized record prefix for segment header.";
      return false;
    }

    TraceFileSegmentHeader segment_header;
    if (::fread(&segment_header,
                sizeof(segment_header),
                1,
                trace_file.get()) !=  1) {
      LOG(ERROR) << "Failed to read segment header.";
      return false;
    }

    size_t aligned_size = AlignUp(segment_header.segment_length,
                                  file_header->block_size);

    if (aligned_size > buffer_size) {
      buffer.reset(reinterpret_cast<uint8*>(::malloc(aligned_size)));
      buffer_size = aligned_size;
    }

    if (::fread(buffer.get(), segment_header.segment_length, 1,
                trace_file.get()) !=  1) {
      LOG(ERROR) << "Failed to read segment.";
      return false;
    }

    if (!ConsumeSegmentEvents(*file_header,
                              segment_header,
                              buffer.get(),
                              segment_header.segment_length)) {
      return false;
    }

    next_segment = AlignUp(
        next_segment + sizeof(segment_prefix) + sizeof(segment_header) +
            segment_header.segment_length,
        file_header->block_size);
  }

  event_handler_->OnProcessEnded(
      base::Time::FromTimeT(static_cast<time_t>(kuint64max)),
      file_header->process_id);

  RemoveProcessInformation(file_header->process_id);

  return true;
}

bool ParseEngineRpc::ConsumeSegmentEvents(
    const TraceFileHeader& file_header,
    const TraceFileSegmentHeader& segment_header,
    uint8* buffer,
    size_t buffer_length) {
  DCHECK(buffer != NULL);
  DCHECK(event_handler_ != NULL);

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
    if (!DispatchEvent(&event_record)) {
      LOG(ERROR) << "Failed to process event of type " << prefix->type << ".";
      return false;
    }

    if (error_occurred()) {
      return false;
    }
  }

  return true;
}

}  // namespace call_trace::parser
}  // namespace call_trace
