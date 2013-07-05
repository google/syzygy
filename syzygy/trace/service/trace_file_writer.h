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
// This file declares the TraceFileWriterFactory class, which provides a
// factory implementation for the default buffer consumer used by the call
// trace service.

#ifndef SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_
#define SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_

#include "base/files/file_path.h"
#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/service/buffer_consumer.h"

namespace trace {
namespace service {

// Forward Declaration.
class Session;
class TraceFileWriterFactory;

// This class implements the interface the buffer consumer thread uses to
// process incoming buffers.
class TraceFileWriter : public BufferConsumer {
 public:
  // Construct a TraceFileWriter instance.
  // @param message_loop The message loop on which this writer instance will
  //     consume buffers. The writer instance does NOT take ownership of the
  //     message_loop. The message_loop must outlive the writer instance.
  // @param trace_directory The directory into which this writer instance will
  //     write the trace file.
  TraceFileWriter(base::MessageLoop* message_loop,
                  const base::FilePath& trace_directory);

  // Initialize this trace file writer.
  // @name BufferConsumer implementation.
  // @{
  virtual bool Open(Session* session) OVERRIDE;
  virtual bool Close(Session* session) OVERRIDE;
  virtual bool ConsumeBuffer(Buffer* buffer) OVERRIDE;
  virtual size_t block_size() const OVERRIDE;
  // @}

 protected:
  // Commit a trace buffer to disk. This will be called on message_loop_.
  void WriteBuffer(Session* session, Buffer* buffer);

  // The message loop on which this trace file writer will do IO.
  base::MessageLoop* const message_loop_;

  // The name of the trace file. Note that we initialize this to the trace
  // directory on construction and calculate the final trace file path on
  // Open().
  base::FilePath trace_file_path_;

  // The handle to the trace file to which buffers are committed.
  base::win::ScopedHandle trace_file_handle_;

  // The block size used when writing to disk. This corresponds to
  // the physical sector size of the disk.
  size_t block_size_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TraceFileWriter);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_
