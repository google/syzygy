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

#include "syzygy/trace/service/session_trace_file_writer_factory.h"

#include "base/file_util.h"
#include "base/message_loop/message_loop.h"
#include "syzygy/trace/service/session_trace_file_writer.h"

namespace trace {
namespace service {

SessionTraceFileWriterFactory::SessionTraceFileWriterFactory(
    base::MessageLoop* message_loop)
    : message_loop_(message_loop), trace_file_directory_(L".") {
  DCHECK(message_loop != NULL);
  DCHECK_EQ(base::MessageLoop::TYPE_IO, message_loop->type());
}

bool SessionTraceFileWriterFactory::SetTraceFileDirectory(
    const base::FilePath& path) {
  DCHECK(!path.empty());
  if (!base::CreateDirectory(path)) {
    LOG(ERROR) << "Failed to create trace file directory '" << path.value()
               << "'.";
    return false;
  }

  trace_file_directory_ = path;
  return true;
}

bool SessionTraceFileWriterFactory::CreateConsumer(
    scoped_refptr<BufferConsumer>* consumer) {
  DCHECK(consumer != NULL);
  DCHECK(message_loop_ != NULL);

  // Allocate a new trace file writer.
  *consumer = new SessionTraceFileWriter(message_loop_, trace_file_directory_);
  return true;
}

}  // namespace service
}  // namespace trace
