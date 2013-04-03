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
// This file declares the TraceFileWriter class, which is the default
// implementation for the buffer consumer used by the call trace service.

#ifndef SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_FACTORY_H_
#define SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_FACTORY_H_

#include <set>

#include "base/files/file_path.h"
#include "base/synchronization/lock.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/service/buffer_consumer.h"

class MessageLoop;

namespace trace {
namespace service {

class TraceFileWriter;

// This class creates manages buffer consumer instances for a call trace
// service instance.
class TraceFileWriterFactory : public BufferConsumerFactory {
 public:
  // construct a TraceFileWriterFactory instance.
  // @param message_loop The message loop on which TraceFileWriter instances
  //     created by this factory will consume buffers. The factory instance
  //     does NOT take ownership of the message_loop. The message_loop must
  //     outlive the factory instance.
  explicit TraceFileWriterFactory(MessageLoop* message_loop);

  // @name BufferConsumerFactory implementation.
  // @{
  virtual bool CreateConsumer(scoped_refptr<BufferConsumer>* consumer) OVERRIDE;
  // @}

  // Sets the trace file directory to which all subsequently created trace
  // file writers will output trace files.
  bool SetTraceFileDirectory(const base::FilePath& path);

  // Get the message loop the trace file writers should use for IO.
  MessageLoop* message_loop() { return message_loop_; }

 protected:
  // The message loop the trace file writers should use for IO.
  MessageLoop* const message_loop_;

  // The directory into which trace file writers will write.
  base::FilePath trace_file_directory_;

  // The set of currently active buffer consumer objects. Protected by lock_.
  std::set<scoped_refptr<BufferConsumer>> active_consumers_;

  // Used to protect access to the set of active consumers.
  base::Lock lock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TraceFileWriterFactory);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_FACTORY_H_
