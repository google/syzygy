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
// This file implements the TraceFileWriter and TraceFileWriterFactory classes
// which provide an implementation and factory, respectively, for the default
// buffer consumer used by the call trace service.

#include "syzygy/trace/service/trace_file_writer_factory.h"

#include <time.h>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/message_loop.h"
#include "base/stringprintf.h"
#include "base/memory/scoped_ptr.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/common/path_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/buffer_pool.h"
#include "syzygy/trace/service/session.h"
#include "syzygy/trace/service/trace_file_writer.h"

namespace trace {
namespace service {

TraceFileWriterFactory::TraceFileWriterFactory(MessageLoop* message_loop)
    : message_loop_(message_loop), trace_file_directory_(L".") {
  DCHECK(message_loop != NULL);
  DCHECK_EQ(MessageLoop::TYPE_IO, message_loop->type());
}

bool TraceFileWriterFactory::SetTraceFileDirectory(const FilePath& path) {
  DCHECK(!path.empty());
  if (!file_util::CreateDirectory(path)) {
    LOG(ERROR) << "Failed to create trace file directory '" << path.value()
               << "'.";
    return false;
  }

  trace_file_directory_ = path;
  return true;
}

bool TraceFileWriterFactory::CreateConsumer(
    scoped_refptr<BufferConsumer>* consumer) {
  DCHECK(consumer != NULL);
  DCHECK(message_loop_ != NULL);

  // Allocate a new trace file writer.
  *consumer = new TraceFileWriter(message_loop_, trace_file_directory_);
  return true;
}

}  // namespace service
}  // namespace trace
