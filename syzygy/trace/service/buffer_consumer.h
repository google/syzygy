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
// This file declares the BufferConsumer and BufferConsumerFactory interfaces.

#ifndef SYZYGY_TRACE_SERVICE_BUFFER_CONSUMER_H_
#define SYZYGY_TRACE_SERVICE_BUFFER_CONSUMER_H_

#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"

namespace trace {
namespace service {

// Forward declarations.
struct Buffer;
class Service;
class Session;

// This class defines the interface the writer thread expects a session's
// buffer consumer to support. This interface is reference counted because
// a given BufferConsumerFactory (see below) is not obligated to hand out a
// new BufferConsumer instance on each request. Where appropriate, a single
// consumer may be shared by multiple sessions.
class BufferConsumer : public base::RefCountedThreadSafe<BufferConsumer> {
 public:
  // Open this consumer for the given session. This affords the buffer
  // consumer the opportunity to perform any per-session initialization
  // it requires.
  virtual bool Open(Session* session) = 0;

  // Inform the BufferConsumer to that this session will no longer be
  // generating buffers to consume. This affords the buffer consumer the
  // opportunity to perform and per-session cleanup it requires. After
  // calling this, the session MUST release all references it holds to the
  // BufferConsumer. The session should not call this until there are no
  // outstanding buffers being held by the consumer (see ConsumeBuffer()).
  virtual bool Close(Session* session) = 0;

  // Consume the given buffer. The session that owns the buffer will be
  // notified when the consumption has completed via a call to
  // Session::RecycleBuffer();
  virtual bool ConsumeBuffer(Buffer* buffer) = 0;

  // Get the block size used when consuming buffers. The buffer consumer will
  // expect that buffers are sized as a multiple of the block size.
  virtual size_t block_size() const = 0;

 protected:
  virtual ~BufferConsumer() = 0 {}
  friend class base::RefCountedThreadSafe<BufferConsumer>;
};

// This class defines the interface the call trace service uses to create
// and manage buffer consumers when sessions are instantiated.
class BufferConsumerFactory {
 public:
  // Creates a new consumer.
  virtual bool CreateConsumer(scoped_refptr<BufferConsumer>* consumer) = 0;
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_BUFFER_CONSUMER_H_
