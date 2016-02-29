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

// Comparison operator. This is out of the anonymous namespace so it can be
// found by the unittest helper.
bool operator==(const Story::PlotLine& pl1, const Story::PlotLine& pl2) {
  if (pl1.size() != pl2.size())
    return false;
  for (size_t i = 0; i < pl1.size(); ++i) {
    if (!pl1[i]->Equals(pl2[i]))
      return false;
  }
  return true;
}

// Comparison operator. This is out of the anonymous namespace so it can be
// found by the unittest helper.
bool operator==(const Story& s1, const Story& s2) {
  if (s1.plot_lines().size() != s2.plot_lines().size())
    return false;
  for (size_t i = 0; i < s1.plot_lines().size(); ++i) {
    if (!(*s1.plot_lines()[i] == *s2.plot_lines()[i]))
      return false;
  }
  return true;
}

TEST(StoryTest, CreatePlotLine) {
  Story s;
  EXPECT_EQ(0u, s.plot_lines().size());
  auto pl = s.CreatePlotLine();
  EXPECT_TRUE(pl);
  EXPECT_EQ(1u, s.plot_lines().size());

  Story::PlotLine* pl2 = new Story::PlotLine();
  EXPECT_EQ(pl2, s.AddPlotLine(scoped_ptr<Story::PlotLine>(pl2)));
  EXPECT_EQ(2u, s.plot_lines().size());
}

TEST(StoryTest, TestSerialization) {
  scoped_ptr<EventInterface> event1(
      new HeapCreateEvent(0, kOptions, kInitialSize, kMaximumSize, kTraceHeap));
  scoped_ptr<EventInterface> event2(
      new HeapAllocEvent(0, kTraceHeap, kFlags, kBytes, kTraceAlloc));
  scoped_ptr<EventInterface> event3(
      new HeapSizeEvent(0, kTraceHeap, kFlags, kTraceAlloc, kSize));
  scoped_ptr<EventInterface> event4(
      new HeapFreeEvent(0, kTraceHeap, kFlags, kTraceAlloc, true));
  scoped_ptr<EventInterface> event5(new HeapDestroyEvent(0, kTraceHeap, true));

  // The following events will either be cross plot line dependencies or have
  // such dependencies.
  scoped_ptr<LinkedEvent> linked_event1(new LinkedEvent(event1.Pass()));
  scoped_ptr<LinkedEvent> linked_event2(new LinkedEvent(event2.Pass()));
  scoped_ptr<LinkedEvent> linked_event4(new LinkedEvent(event4.Pass()));
  scoped_ptr<LinkedEvent> linked_event5(new LinkedEvent(event5.Pass()));

  // Alloc depends on Create, as it would be on another thread.
  linked_event2->AddDep(linked_event1.get());

  // Similarly the heap can't be detroyed until all use of it has been
  // completed.
  linked_event5->AddDep(linked_event4.get());

  scoped_ptr<Story::PlotLine> plot_line1(new Story::PlotLine());
  scoped_ptr<Story::PlotLine> plot_line2(new Story::PlotLine());

  // One plot line creates and frees the heap.
  plot_line1->push_back(linked_event1.Pass());
  plot_line1->push_back(linked_event5.Pass());

  // Another plot line owns the allocation.
  plot_line2->push_back(linked_event2.Pass());
  plot_line2->push_back(event3.Pass());
  plot_line2->push_back(linked_event4.Pass());

  // Create a story to wrap it all up.
  Story story;
  story.AddPlotLine(plot_line1.Pass());
  story.AddPlotLine(plot_line2.Pass());

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
