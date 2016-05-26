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
// This file declares the SessionTraceFileWriterFactory class, which provides a
// factory implementation for the default buffer consumer used by the call
// trace service.

#ifndef SYZYGY_TRACE_SERVICE_SESSION_TRACE_FILE_WRITER_H_
#define SYZYGY_TRACE_SERVICE_SESSION_TRACE_FILE_WRITER_H_

#include "base/files/file_path.h"
#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/service/buffer_consumer.h"
#include "syzygy/trace/service/trace_file_writer.h"

namespace trace {
namespace service {

// Forward Declaration.
class Session;
class SessionTraceFileWriterFactory;

// This class implements the interface the buffer consumer thread uses to
// process incoming buffers.
class SessionTraceFileWriter : public BufferConsumer {
 public:
  // Construct a SessionTraceFileWriter instance.
  // @param message_loop The message loop on which this writer instance will
  //     consume buffers. The writer instance does NOT take ownership of the
  //     message_loop. The message_loop must outlive the writer instance.
  // @param trace_directory The directory into which this writer instance will
  //     write the trace file.
  SessionTraceFileWriter(base::MessageLoop* message_loop,
                         const base::FilePath& trace_directory);

  // Initialize this trace file writer.
  // @name BufferConsumer implementation.
  // @{
  bool Open(Session* session) override;
  bool Close(Session* session) override;
  bool ConsumeBuffer(Buffer* buffer) override;
  size_t block_size() const override;
  // @}

 protected:
  // Commit a trace buffer to disk. This will be called on message_loop_.
  void WriteBuffer(scoped_refptr<Session>, Buffer* buffer);

  // The message loop on which this trace file writer will do IO.
  base::MessageLoop* const message_loop_;

  // The name of the trace file. Note that we initialize this to the trace
  // directory on construction and calculate the final trace file path on
  // Open().
  base::FilePath trace_file_path_;

  // This is used for committing actual buffers to disk.
  TraceFileWriter writer_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SessionTraceFileWriter);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_SESSION_TRACE_FILE_WRITER_H_
