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

#include "base/memory/scoped_vector.h"
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

  Story() {}

  // Add a PlotLine to the Story. Story takes ownership of all the PlotLines
  // that it stores.
  // @param event a scoped_ptr to the PlotLine to be added to the Story.
  // @returns a pointer to the stored PlotLine.
  PlotLine* AddPlotLine(scoped_ptr<PlotLine> plot_line);

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

 private:
  ScopedVector<PlotLine> plot_lines_;

  DISALLOW_COPY_AND_ASSIGN(Story);
};

}  // namespace bard

#endif  // SYZYGY_BARD_STORY_H_
