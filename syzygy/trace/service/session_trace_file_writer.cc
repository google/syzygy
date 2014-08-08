// Copyright 2012 Google Inc. All Rights Reserved.
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
// This file implements the SessionTraceFileWriter and
// SessionTraceFileWriterFactory classes which provide an implementation and
// factory, respectively, for the default buffer consumer used by the call trace
// service.

#include "syzygy/trace/service/session_trace_file_writer.h"

#include "base/bind.h"
#include "base/file_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/buffer_pool.h"
#include "syzygy/trace/service/mapped_buffer.h"
#include "syzygy/trace/service/session.h"

namespace trace {
namespace service {

SessionTraceFileWriter::SessionTraceFileWriter(
    base::MessageLoop* message_loop, const base::FilePath& trace_directory)
    : message_loop_(message_loop),
      trace_file_path_(trace_directory) {
  DCHECK(message_loop != NULL);
  DCHECK(!trace_directory.empty());
}

bool SessionTraceFileWriter::Open(Session* session) {
  DCHECK(session != NULL);

  if (!base::CreateDirectory(trace_file_path_)) {
    LOG(ERROR) << "Failed to create trace directory: '"
               << trace_file_path_.value() << "'.";
    return false;
  }

  // Append the trace file name onto the trace file directory we stored on
  // construction.
  base::FilePath basename = TraceFileWriter::GenerateTraceFileBaseName(
      session->client_info());
  trace_file_path_ = trace_file_path_.Append(basename);

  // Open the trace file and write the header.
  if (!writer_.Open(trace_file_path_) ||
      !writer_.WriteHeader(session->client_info())) {
    return false;
  }

  return true;
}

bool SessionTraceFileWriter::Close(Session* /* session */) {
  return true;
}

bool SessionTraceFileWriter::ConsumeBuffer(Buffer* buffer) {
  DCHECK(buffer != NULL);
  DCHECK(buffer->session != NULL);
  DCHECK(message_loop_ != NULL);

  message_loop_->PostTask(FROM_HERE,
                          base::Bind(&SessionTraceFileWriter::WriteBuffer,
                                     this,
                                     scoped_refptr<Session>(buffer->session),
                                     base::Unretained(buffer)));

  return true;
}

size_t SessionTraceFileWriter::block_size() const {
  return writer_.block_size();
}

void SessionTraceFileWriter::WriteBuffer(Session* session, Buffer* buffer) {
  DCHECK(session != NULL);
  DCHECK(buffer != NULL);
  DCHECK_EQ(session, buffer->session);
  DCHECK_EQ(Buffer::kPendingWrite, buffer->state);
  DCHECK_EQ(base::MessageLoop::current(), message_loop_);

  MappedBuffer mapped_buffer(buffer);
  if (!mapped_buffer.Map())
    return;

  // We deliberately ignore the return status. However, this will log if
  // anything goes wrong.
  writer_.WriteRecord(mapped_buffer.data(), buffer->buffer_size);

  // It's entirely possible for this buffer to be handed out to another client
  // and for the service to be forcibly shutdown before the client has had a
  // chance to even touch the buffer. In that case, we'll end up writing the
  // buffer again. We clear the RecordPrefix and the TraceFileSegmentHeader so
  // that we'll at least see the buffer as empty and write nothing.
  ::memset(mapped_buffer.data(), 0,
           sizeof(RecordPrefix) + sizeof(TraceFileSegmentHeader));

  mapped_buffer.Unmap();
  session->RecycleBuffer(buffer);
}

}  // namespace service
}  // namespace trace
