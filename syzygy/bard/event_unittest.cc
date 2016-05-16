// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/bard/event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_realloc_event.h"
#include "syzygy/bard/events/heap_set_information_event.h"
#include "syzygy/bard/events/heap_size_event.h"

namespace bard {

// A template class for generating a test instance of an event. Specializations
// for each event type are below.
template <typename EventType>
std::unique_ptr<EventInterface> CreateTestEvent();

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapAllocEvent>() {
  return std::unique_ptr<EventInterface>(
      new events::HeapAllocEvent(0, reinterpret_cast<HANDLE>(0x1000), 0x1, 47,
                                 reinterpret_cast<LPVOID>(0x2000)));
}

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapCreateEvent>() {
  return std::unique_ptr<EventInterface>(new events::HeapCreateEvent(
      0, 0, 100, 200, reinterpret_cast<HANDLE>(0x1000)));
}

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapDestroyEvent>() {
  return std::unique_ptr<EventInterface>(
      new events::HeapDestroyEvent(0, reinterpret_cast<HANDLE>(0x1000), true));
}

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapFreeEvent>() {
  return std::unique_ptr<EventInterface>(
      new events::HeapFreeEvent(0, reinterpret_cast<HANDLE>(0x1000), 0,
                                reinterpret_cast<LPVOID>(0x2000), true));
}

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapReAllocEvent>() {
  return std::unique_ptr<EventInterface>(new events::HeapReAllocEvent(
      0, reinterpret_cast<HANDLE>(0x1000), 0, reinterpret_cast<LPVOID>(0x2000),
      123, reinterpret_cast<LPVOID>(0x3000)));
}

template <>
std::unique_ptr<EventInterface>
CreateTestEvent<events::HeapSetInformationEvent>() {
  return std::unique_ptr<EventInterface>(new events::HeapSetInformationEvent(
      0, reinterpret_cast<HANDLE>(0x1000),
      static_cast<HEAP_INFORMATION_CLASS>(0), reinterpret_cast<PVOID>(0x2000),
      100, false));
}

template <>
std::unique_ptr<EventInterface> CreateTestEvent<events::HeapSizeEvent>() {
  return std::unique_ptr<EventInterface>(
      new events::HeapSizeEvent(0, reinterpret_cast<HANDLE>(0x1000), 0,
                                reinterpret_cast<LPCVOID>(0x2000), 233));
}

// Test helper for testing the EventInterface abstract serialization mechanism.
template <typename EventType>
void EventSerializationTest() {
  core::ByteVector bytes;

  core::ScopedOutStreamPtr out_stream;
  out_stream.reset(core::CreateByteOutStream(std::back_inserter(bytes)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  std::unique_ptr<EventInterface> e0 = CreateTestEvent<EventType>();
  EXPECT_TRUE(EventInterface::Save(e0.get(), &out_archive));
  EXPECT_TRUE(out_archive.Flush());

  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(bytes.begin(), bytes.end()));
  core::NativeBinaryInArchive in_archive(in_stream.get());
  std::unique_ptr<EventInterface> e1 =
      std::move(EventInterface::Load(&in_archive));
  EXPECT_NE(static_cast<EventInterface*>(nullptr), e1.get());

  EXPECT_TRUE(e0->Equals(e1.get()));
}

// Test abstract serialization of each event type.
TEST(EventInterfaceTest, AbstractSerialization) {
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapAllocEvent>());
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapCreateEvent>());
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapDestroyEvent>());
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapFreeEvent>());
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapReAllocEvent>());
  EXPECT_NO_FATAL_FAILURE(
      EventSerializationTest<events::HeapSetInformationEvent>());
  EXPECT_NO_FATAL_FAILURE(EventSerializationTest<events::HeapSizeEvent>());

  static_assert(static_cast<int>(EventInterface::kHeapSizeEvent + 1) ==
                    static_cast<int>(EventInterface::kMaxEventType),
                "all event types must be tested");
}

}  // namespace bard
