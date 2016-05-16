// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/trace/service/mapped_buffer.h"

#include "gtest/gtest.h"
#include "syzygy/trace/service/buffer_consumer.h"
#include "syzygy/trace/service/buffer_pool.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/session.h"

namespace trace {
namespace service {

namespace {

// A dummy buffer consumer for use with our dummy session.
class DummyBufferConsumer : public BufferConsumer {
 public:
  virtual ~DummyBufferConsumer() { }
  virtual bool Open(Session* session) override { return true; }
  virtual bool Close(Session* session) override { return true; }
  virtual bool ConsumeBuffer(Buffer* buffer) override { return true; }
  virtual size_t block_size() const override { return 1024; }
};

// A factory for producing DummyBufferConsumer instances.
class DummyBufferConsumerFactory : public BufferConsumerFactory {
 public:
  virtual bool CreateConsumer(
      scoped_refptr<BufferConsumer>* consumer) override {
    *consumer = new DummyBufferConsumer();
    return true;
  }
};

class MappedBufferTest : public testing::Test {
 public:
  // This needs to be <= the system allocation granularity (which is 64kb).
  static const size_t kBufferSize = 4096;

  MappedBufferTest() : b1(NULL), b2(NULL) {
    SYSTEM_INFO sys_info = {};
    ::GetSystemInfo(&sys_info);
    DCHECK_LT(kBufferSize, sys_info.dwAllocationGranularity);
  }

  virtual void SetUp() override {
    service.reset(new Service(&dummy_buffer_consumer_factory));
    session = new Session(service.get());

    pool.reset(new BufferPool());
    ASSERT_TRUE(pool->Init(session.get(), 2, kBufferSize));

    b1 = pool->begin();
    b2 = b1 + 1;
    ASSERT_EQ(2, pool->end() - pool->begin());
  }

  virtual void TearDown() override {
    b1 = NULL;
    b2 = NULL;

    pool.reset();
    session = NULL;
    service.reset();
  }

  // These are needed because they are all injected dependencies of each other,
  // and ultimately a session is an injected dependency of a BufferPool.
  // However, I don't need them to be actually running as MappedBuffer
  // interaction with BufferPool is limited to the memory mapped file handle.
  DummyBufferConsumerFactory dummy_buffer_consumer_factory;
  std::unique_ptr<Service> service;
  scoped_refptr<Session> session;
  std::unique_ptr<BufferPool> pool;
  Buffer* b1;
  Buffer* b2;
};

// A simple wrapper that exposes the innards of a mapped buffer.
class TestMappedBuffer : public MappedBuffer {
 public:
  explicit TestMappedBuffer(Buffer* buffer) : MappedBuffer(buffer) { }
  Buffer* buffer() const { return buffer_; }
  uint8_t* base() const { return base_; }
};

}  // namespace

TEST_F(MappedBufferTest, MapAndUnmap) {
  TestMappedBuffer mb(b1);
  EXPECT_EQ(b1, mb.buffer());
  EXPECT_TRUE(mb.base() == NULL);
  EXPECT_TRUE(mb.data() == NULL);
  EXPECT_FALSE(mb.IsMapped());

  // Do a no-op unmap.
  EXPECT_TRUE(mb.Unmap());
  EXPECT_EQ(b1, mb.buffer());
  EXPECT_TRUE(mb.base() == NULL);
  EXPECT_TRUE(mb.data() == NULL);
  EXPECT_FALSE(mb.IsMapped());

  // Map the buffer.
  EXPECT_TRUE(mb.Map());
  EXPECT_EQ(b1, mb.buffer());
  EXPECT_TRUE(mb.base() != NULL);
  EXPECT_TRUE(mb.data() != NULL);
  EXPECT_EQ(mb.base(), mb.data());
  EXPECT_TRUE(mb.IsMapped());
  uint8_t* base = mb.base();
  uint8_t* data = mb.data();

  // Do a no-op map.
  EXPECT_TRUE(mb.Map());
  EXPECT_EQ(b1, mb.buffer());
  EXPECT_TRUE(mb.base() != NULL);
  EXPECT_TRUE(mb.data() != NULL);
  EXPECT_EQ(mb.base(), mb.data());
  EXPECT_EQ(base, mb.base());
  EXPECT_EQ(data, mb.data());
  EXPECT_TRUE(mb.IsMapped());

  // Unmap the buffer.
  EXPECT_TRUE(mb.Unmap());
  EXPECT_EQ(b1, mb.buffer());
  EXPECT_TRUE(mb.base() == NULL);
  EXPECT_TRUE(mb.data() == NULL);
  EXPECT_FALSE(mb.IsMapped());
}

TEST_F(MappedBufferTest, AlignmentCalculationIsCorrect) {
  TestMappedBuffer mb(b2);

  // Map the buffer.
  EXPECT_TRUE(mb.Map());
  EXPECT_TRUE(mb.base() != NULL);
  EXPECT_TRUE(mb.data() != NULL);
  EXPECT_EQ(mb.data(), mb.base() + kBufferSize);
}

TEST_F(MappedBufferTest, MappedViewIsReaped) {
  MEMORY_BASIC_INFORMATION info = {};
  SIZE_T ret = 0;
  uint8_t* base = NULL;

  {
    TestMappedBuffer mb(b1);
    mb.Map();
    base = mb.base();
    EXPECT_TRUE(base != NULL);
    ret = ::VirtualQuery(base, &info, sizeof(info));
    EXPECT_EQ(sizeof(info), ret);
    EXPECT_EQ(base, info.BaseAddress);
    EXPECT_LE(kBufferSize, info.RegionSize);
    EXPECT_EQ(MEM_MAPPED, info.Type);

    // Test that the mapping is reaped when unmap is explicitly called.
    mb.Unmap();
    ret = ::VirtualQuery(base, &info, sizeof(info));
    EXPECT_EQ(sizeof(info), ret);
    EXPECT_EQ(MEM_FREE, info.State);

    mb.Map();
    base = mb.base();
    EXPECT_TRUE(base != NULL);
    ret = ::VirtualQuery(base, &info, sizeof(info));
    EXPECT_EQ(sizeof(info), ret);
    EXPECT_EQ(base, info.BaseAddress);
    EXPECT_LE(kBufferSize, info.RegionSize);
    EXPECT_EQ(MEM_MAPPED, info.Type);
  }

  // And also make sure it is reaped when the object goes out of scope.
  ret = ::VirtualQuery(base, &info, sizeof(info));
  EXPECT_EQ(sizeof(info), ret);
  EXPECT_EQ(MEM_FREE, info.State);
}

}  // namespace service
}  // namespace trace
