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
//
// Declares Story, a class encapsulating a collection of PlotLines. Each
// PlotLine is an ordered sequence of events that will be played independently
// (ie. on their own threads), with potential interactions between them via
// the Backdrop and any causality constraints, themselves represented via
// LinkedEvents.
//
// The serialized file is organized as follows:
//
// - PlotLines
//   - number of plot lines
//   - PlotLine0
//     - number of events in plot line
//     - Event0
//       - type of event 0
//       - serialization of event 0
//     - ... repeat for other events ...
//   - ... repeated for other plot lines ...
// - causality constraints (the number of linked events is implicit)
//   - (linked event id) of event with input constraints
//   - number of input constraints
//   - (linked event id) of input constraint 0
//   - ... repeated for other constraints ...

#ifndef SYZYGY_BARD_STORY_H_
#define SYZYGY_BARD_STORY_H_

#include "base/callback.h"
#include "base/memory/scoped_vector.h"
#include "base/threading/simple_thread.h"
#include "syzygy/bard/event.h"
#include "syzygy/core/serialization.h"

namespace bard {

// Container class for storing and serializing PlotLines.
class Story {
 public:
  // A PlotLine is a simple ordered sequence of events. At some point we may
  // need additional functionality on this class but for now a vector does the
  // job.
  using PlotLine = ScopedVector<EventInterface>;

  // PlotLine playback thread runner.
  class PlotLineRunner;

  // Some constants used in serialization.
  static const uint32_t kBardMagic = 0xBA4D7355;
  static const uint32_t kBardVersion = 1;

  Story() {}

  // Add a PlotLine to the Story. Story takes ownership of all the PlotLines
  // that it stores.
  // @param event a std::unique_ptr to the PlotLine to be added to the Story.
  // @returns a pointer to the stored PlotLine.
  PlotLine* AddPlotLine(std::unique_ptr<PlotLine> plot_line);

  // Creates a plotline, adding it to this story.
  // @returns a pointer to the created plotline.
  PlotLine* CreatePlotLine();

  // @name Serialization methods.
  // @{
  bool Save(core::OutArchive* out_archive) const;
  bool Load(core::InArchive* in_archive);
  // @}

  // Accessor for unittesting.
  const ScopedVector<PlotLine>& plot_lines() const { return plot_lines_; }

  // Plays this story against the provided backdrop. Spins up a thread per
  // plot line and plays the events back as fast as possible on each thread.
  bool Play(void* backdrop);

  // For unittesting.
  bool operator==(const Story& story) const;

 private:
  ScopedVector<PlotLine> plot_lines_;

  DISALLOW_COPY_AND_ASSIGN(Story);
};

// Thread main body for playing back all events on a PlotLine. Since there is
// lots of waiting/signaling between the various threads it is impossible for
// one thread to exit with an error and the rest of them to hang. Thus each
// thread communicates that it has completed via a callback.
//
// This uses a PlatformThread::Delegate rather than base::SimpleThread or other
// implementations as those have the expectation that Join has been called for
// each thread. The current implementation can't support this in the general
// case as some thread's may hang if others exit with an error, meaning they
// are not guaranteed to be joinable.
class Story::PlotLineRunner : public base::PlatformThread::Delegate {
 public:
  // Invoked to indicate that this runner has completed.
  using OnCompleteCallback = base::Callback<void(PlotLineRunner*)>;

  PlotLineRunner(void* backdrop, PlotLine* plot_line);
  ~PlotLineRunner() override {}

  void set_on_complete(OnCompleteCallback on_complete) {
    on_complete_ = on_complete;
  }

  // @returns true if the playback failed.
  bool Failed() const { return failed_event_ != nullptr; }

  // @returns the event that failed during playback, if an event failed.
  EventInterface* failed_event() const { return failed_event_; }

  // Implementation of PlatformThread::Delegate.
  void ThreadMain() override;

  // For starting and stopping the thread.
  void Start();
  void Join();

 private:
  void RunImpl();

  void* backdrop_;
  PlotLine* plot_line_;

  OnCompleteCallback on_complete_;

  // If an error occurs, this is left pointing at the event that failed.
  // Useful for debugging.
  EventInterface* failed_event_;

  base::PlatformThreadHandle handle_;

  DISALLOW_COPY_AND_ASSIGN(PlotLineRunner);
};

}  // namespace bard

// Comparison operator for PlotLines.
// @param pl1 The first plotline to compare.
// @param pl2 The second plotline to compare.
// @returns true if the two plotlines are equal, false otherwise.
// @note This is in the root namespace so its found by test fixtures.
bool operator==(const bard::Story::PlotLine& pl1,
                const bard::Story::PlotLine& pl2);

#endif  // SYZYGY_BARD_STORY_H_
