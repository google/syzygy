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

#include "syzygy/bard/events/heap_alloc_event.h"
#include "syzygy/bard/events/heap_create_event.h"
#include "syzygy/bard/events/heap_destroy_event.h"
#include "syzygy/bard/events/heap_free_event.h"
#include "syzygy/bard/events/heap_realloc_event.h"
#include "syzygy/bard/events/heap_set_information_event.h"
#include "syzygy/bard/events/heap_size_event.h"
#include "syzygy/bard/events/linked_event.h"

namespace bard {

namespace {

using events::LinkedEvent;

}  // namespace

Story::PlotLine* Story::AddPlotLine(scoped_ptr<PlotLine> plot_line) {
  PlotLine* pl = plot_line.get();
  plot_lines_.push_back(plot_line.Pass());
  return pl;
}

Story::PlotLine* Story::CreatePlotLine() {
  PlotLine* plot_line = new PlotLine();
  plot_lines_.push_back(plot_line);
  return plot_line;
}

bool Story::Save(core::OutArchive* out_archive) const {
  std::map<const LinkedEvent*, size_t> linked_event_ids;

  // Serialize the number of plot lines.
  out_archive->Save(plot_lines_.size());

  // Save each plot line.
  for (PlotLine* plot_line : plot_lines_) {
    if (!out_archive->Save(plot_line->size())) {
      return false;
    }

    for (const EventInterface* event : *plot_line) {
      if (!EventInterface::Save(event, out_archive))
        return false;

      // Assign an integer ID to linked events so that the connections
      // between them can be expressed.
      if (event->type() == EventInterface::kLinkedEvent) {
        const LinkedEvent* linked_event =
            reinterpret_cast<const LinkedEvent*>(event);
        linked_event_ids.insert(
            std::make_pair(linked_event, linked_event_ids.size()));
      }
    }
  }

  // Serialize the linked event connections.
  for (auto event_id_pair : linked_event_ids) {
    const LinkedEvent* linked_event = event_id_pair.first;

    // Save the ID of this event and the number of input dependencies.
    if (!out_archive->Save(event_id_pair.second))
      return false;
    if (!out_archive->Save(linked_event->deps().size()))
      return false;

    // Save the ID of each input dependency.
    for (auto dep : linked_event->deps()) {
      auto it = linked_event_ids.find(dep);
      DCHECK(it != linked_event_ids.end());
      if (!out_archive->Save(it->second))
        return false;
    }
  }

  return true;
}

bool Story::Load(core::InArchive* in_archive) {
  std::vector<LinkedEvent*> linked_events_by_id;

  size_t plot_line_count = 0;
  if (!in_archive->Load(&plot_line_count))
    return false;

  // Read the plot lines.
  for (size_t i = 0; i < plot_line_count; ++i) {
    scoped_ptr<PlotLine> plot_line(new PlotLine());

    // Read the events.
    size_t event_count = 0;
    if (!in_archive->Load(&event_count))
      return false;
    for (size_t j = 0; j < event_count; ++j) {
      scoped_ptr<EventInterface> event = EventInterface::Load(in_archive);
      if (!event.get())
        return false;

      if (event->type() == EventInterface::kLinkedEvent) {
        LinkedEvent* linked_event = reinterpret_cast<LinkedEvent*>(event.get());
        linked_events_by_id.push_back(linked_event);
      }

      plot_line->push_back(event.Pass());
    }

    plot_lines_.push_back(plot_line.Pass());
  }

  // Deserialize event dependencies.
  for (size_t i = 0; i < linked_events_by_id.size(); ++i) {
    size_t event_id = 0;
    if (!in_archive->Load(&event_id))
      return false;
    DCHECK_GT(linked_events_by_id.size(), event_id);
    LinkedEvent* event = linked_events_by_id[event_id];

    size_t dep_count = 0;
    if (!in_archive->Load(&dep_count))
      return false;

    // Deserialize the dependencies and emit them.
    for (size_t j = 0; j < dep_count; ++j) {
      size_t dep_id = 0;
      if (!in_archive->Load(&dep_id))
        return false;
      DCHECK_GT(linked_events_by_id.size(), dep_id);
      LinkedEvent* dep = linked_events_by_id[dep_id];
      event->AddDep(dep);
    }
  }

  return true;
}

bool Story::Play(void* backdrop) {
  // Create all of the runners and threads for them.
  ScopedVector<PlotLineRunner> runners;
  for (auto plot_line : plot_lines_)
    runners.push_back(new PlotLineRunner(backdrop, plot_line));

  // Start the threads.
  for (auto runner : runners)
    runner->Start();

  // Join the threads and collect their results.
  bool success = true;
  for (auto runner : runners) {
    runner->Join();
    if (runner->Failed())
      success = false;
  }

  return success;
}

Story::PlotLineRunner::PlotLineRunner(void* backdrop, PlotLine* plot_line)
    : base::SimpleThread("PlotLineRunner"),
      backdrop_(backdrop),
      plot_line_(plot_line),
      failed_event_(nullptr) {
}

void Story::PlotLineRunner::Run() {
  for (auto evt : *plot_line_) {
    if (!evt->Play(backdrop_)) {
      failed_event_ = evt;
      return;
    }
  }
}

}  // namespace bard
