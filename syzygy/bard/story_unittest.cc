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

#include "syzygy/bard/story.h"

#include <vector>

#include "base/atomicops.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_size_event.h"
#include "syzygy/bard/events/linked_event.h"
#include "syzygy/core/unittest_util.h"

namespace bard {
namespace {

using events::LinkedEvent;

using events::HeapAllocEvent;
using events::HeapCreateEvent;
using events::HeapDestroyEvent;
using events::HeapFreeEvent;
using events::HeapSizeEvent;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPVOID kLiveAlloc = reinterpret_cast<LPVOID>(0x4820BC7A);
const LPVOID kTraceAlloc = reinterpret_cast<LPVOID>(0xF1D97AE4);
const DWORD kFlags = 1;
const DWORD kOptions = 0;
const SIZE_T kBytes = 100;
const SIZE_T kSize = 100;
const SIZE_T kInitialSize = 1;
const SIZE_T kMaximumSize = 1000;

class InvalidEvent : public EventInterface {
 public:
  EventType type() const override { return EventType::kMaxEventType; }

  bool Play(void* backdrop) override { return true; }
  bool Equals(const EventInterface*) const override { return false; }
};

// A simple event that simply returns false. Used for testing playback.
class FailedEvent : public EventInterface {
 public:
  EventType type() const override { return EventType::kMaxEventType; }

  bool Play(void* backdrop) override { return false; }
  bool Equals(const EventInterface*) const override { return false; }
};

// A simple event that appends its ID to a vector. Used for testing playback.
class AppendEvent : public EventInterface {
 public:
  explicit AppendEvent(uint32_t id) : id_(id) {}
  EventType type() const override { return EventType::kMaxEventType; }

  bool Play(void* backdrop) override {
    auto v = reinterpret_cast<std::vector<uint32_t>*>(backdrop);
    v->push_back(id_);
    return true;
  }
  bool Equals(const EventInterface*) const override { return false; }

 private:
  uint32_t id_;
};

// A simple event that increments a counter atomically. Used for testing
// playback.
class IncrementEvent : public EventInterface {
 public:
  explicit IncrementEvent(uint32_t amount) : amount_(amount) {}
  EventType type() const override { return EventType::kMaxEventType; }

  bool Play(void* backdrop) override {
    auto atomic = reinterpret_cast<volatile base::subtle::Atomic32*>(backdrop);
    base::subtle::Barrier_AtomicIncrement(atomic, amount_);
    return true;
  }
  bool Equals(const EventInterface*) const override { return false; }

 private:
  uint32_t amount_;
};

}  // namespace

TEST(StoryTest, CreatePlotLine) {
  Story s;
  EXPECT_EQ(0u, s.plot_lines().size());
  auto pl = s.CreatePlotLine();
  EXPECT_TRUE(pl);
  EXPECT_EQ(1u, s.plot_lines().size());

  Story::PlotLine* pl2 = new Story::PlotLine();
  EXPECT_EQ(pl2, s.AddPlotLine(std::unique_ptr<Story::PlotLine>(pl2)));
  EXPECT_EQ(2u, s.plot_lines().size());
}

TEST(StoryTest, TestSerialization) {
  std::unique_ptr<EventInterface> event1(
      new HeapCreateEvent(0, kOptions, kInitialSize, kMaximumSize, kTraceHeap));
  std::unique_ptr<EventInterface> event2(
      new HeapAllocEvent(0, kTraceHeap, kFlags, kBytes, kTraceAlloc));
  std::unique_ptr<EventInterface> event3(
      new HeapSizeEvent(0, kTraceHeap, kFlags, kTraceAlloc, kSize));
  std::unique_ptr<EventInterface> event4(
      new HeapFreeEvent(0, kTraceHeap, kFlags, kTraceAlloc, true));
  std::unique_ptr<EventInterface> event5(
      new HeapDestroyEvent(0, kTraceHeap, true));

  // The following events will either be cross plot line dependencies or have
  // such dependencies.
  std::unique_ptr<LinkedEvent> linked_event1(
      new LinkedEvent(std::move(event1)));
  std::unique_ptr<LinkedEvent> linked_event2(
      new LinkedEvent(std::move(event2)));
  std::unique_ptr<LinkedEvent> linked_event4(
      new LinkedEvent(std::move(event4)));
  std::unique_ptr<LinkedEvent> linked_event5(
      new LinkedEvent(std::move(event5)));

  // Alloc depends on Create, as it would be on another thread.
  linked_event2->AddDep(linked_event1.get());

  // Similarly the heap can't be detroyed until all use of it has been
  // completed.
  linked_event5->AddDep(linked_event4.get());

  std::unique_ptr<Story::PlotLine> plot_line1(new Story::PlotLine());
  std::unique_ptr<Story::PlotLine> plot_line2(new Story::PlotLine());

  // One plot line creates and frees the heap.
  plot_line1->push_back(linked_event1.release());
  plot_line1->push_back(linked_event5.release());

  // Another plot line owns the allocation.
  plot_line2->push_back(linked_event2.release());
  plot_line2->push_back(event3.release());
  plot_line2->push_back(linked_event4.release());

  // Create a story to wrap it all up.
  Story story;
  story.AddPlotLine(std::move(plot_line1));
  story.AddPlotLine(std::move(plot_line2));

  EXPECT_TRUE(testing::TestSerialization(story));
}

TEST(PlotLineRunnerTest, StopOnFailedEvent) {
  Story::PlotLine plot_line;
  plot_line.push_back(new AppendEvent(0));
  plot_line.push_back(new FailedEvent());
  plot_line.push_back(new AppendEvent(1));

  std::vector<uint32_t> v;
  Story::PlotLineRunner runner(&v, &plot_line);
  runner.Start();
  runner.Join();

  EXPECT_TRUE(runner.Failed());
  EXPECT_EQ(plot_line[1], runner.failed_event());
  EXPECT_THAT(v, testing::ElementsAre(0));
}

TEST(PlotLineRunnerTest, Succeeds) {
  Story::PlotLine plot_line;
  plot_line.push_back(new AppendEvent(0));
  plot_line.push_back(new AppendEvent(1));
  plot_line.push_back(new AppendEvent(2));

  std::vector<uint32_t> v;
  Story::PlotLineRunner runner(&v, &plot_line);
  runner.Start();
  runner.Join();

  EXPECT_FALSE(runner.Failed());
  EXPECT_EQ(nullptr, runner.failed_event());
  EXPECT_THAT(v, testing::ElementsAre(0, 1, 2));
}

TEST(StoryTest, PlaybackStopsAndFails) {
  Story story;

  auto plot_line = story.CreatePlotLine();
  plot_line->push_back(new AppendEvent(0));
  plot_line->push_back(new FailedEvent());
  plot_line->push_back(new AppendEvent(1));

  std::vector<uint32_t> v;
  EXPECT_FALSE(story.Play(&v));
  EXPECT_THAT(v, testing::ElementsAre(0));
}

TEST(StoryTest, PlaybackSucceeds) {
  Story story;

  // 10 plotlines (threads) with 10000 events each was sufficient to generate
  // race conditions on a Z600.
  uint32_t sum = 0;
  for (size_t i = 0; i < 10; ++i) {
    auto pl = story.CreatePlotLine();;
    for (size_t j = 0; j < 10000; ++j) {
      pl->push_back(new IncrementEvent(j + i));
      sum += j + i;
    }
  }

  base::subtle::Atomic32 atomic = 0;
  EXPECT_TRUE(story.Play(&atomic));
  EXPECT_EQ(sum, atomic);
}

}  // namespace bard
