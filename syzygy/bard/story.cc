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

#include "base/bind.h"
#include "base/synchronization/condition_variable.h"
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

Story::PlotLine* Story::AddPlotLine(std::unique_ptr<PlotLine> plot_line) {
  PlotLine* pl = plot_line.get();
  plot_lines_.push_back(plot_line.release());
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
    std::unique_ptr<PlotLine> plot_line(new PlotLine());

    // Read the events.
    size_t event_count = 0;
    if (!in_archive->Load(&event_count))
      return false;
    for (size_t j = 0; j < event_count; ++j) {
      std::unique_ptr<EventInterface> event = EventInterface::Load(in_archive);
      if (!event.get())
        return false;

      if (event->type() == EventInterface::kLinkedEvent) {
        LinkedEvent* linked_event = reinterpret_cast<LinkedEvent*>(event.get());
        linked_events_by_id.push_back(linked_event);
      }

      plot_line->push_back(event.release());
    }

    plot_lines_.push_back(plot_line.release());
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

namespace {

struct RunnerInfo {
  RunnerInfo() : cv(&lock), completed_count(0), failed(nullptr) {}

  base::Lock lock;
  base::ConditionVariable cv;
  size_t completed_count;
  Story::PlotLineRunner* failed;
};

// Callback used to keep track of which runners have finished.
void OnComplete(RunnerInfo* info, Story::PlotLineRunner* runner) {
  DCHECK_NE(static_cast<RunnerInfo*>(nullptr), info);
  DCHECK_NE(static_cast<Story::PlotLineRunner*>(nullptr), runner);

  base::AutoLock auto_lock(info->lock);
  ++info->completed_count;
  if (runner->Failed())
    info->failed = runner;
  info->cv.Signal();
}

}  // namespace

bool Story::Play(void* backdrop) {
  // Set up the callback for each runner to invoke.
  RunnerInfo info;
  auto on_complete = base::Bind(&OnComplete, base::Unretained(&info));

  // Create all of the runners and threads for them.
  ScopedVector<PlotLineRunner> runners;
  for (auto plot_line : plot_lines_) {
    auto runner = new PlotLineRunner(backdrop, plot_line);
    runner->set_on_complete(on_complete);
    runners.push_back(runner);
  }

  // Start the threads.
  for (auto runner : runners)
    runner->Start();

  // Wait for all threads to finish successfully, or for one to fail.
  bool success = true;
  while (true) {
    // Wait for at least one runner to complete.
    base::AutoLock auto_lock(info.lock);
    info.cv.Wait();

    if (info.failed) {
      success = false;
      break;
    }

    if (info.completed_count == runners.size())
      break;
  }

  return success;
}

bool Story::operator==(const Story& story) const {
  if (plot_lines().size() != story.plot_lines().size())
    return false;
  for (size_t i = 0; i < plot_lines().size(); ++i) {
    if (!(*plot_lines()[i] == *story.plot_lines()[i]))
      return false;
  }
  return true;
}

Story::PlotLineRunner::PlotLineRunner(void* backdrop, PlotLine* plot_line)
    : backdrop_(backdrop),
      plot_line_(plot_line),
      failed_event_(nullptr) {
}

void Story::PlotLineRunner::ThreadMain() {
  base::PlatformThread::SetName("PlotLineRunner");
  RunImpl();
  if (!on_complete_.is_null())
    on_complete_.Run(this);
}

void Story::PlotLineRunner::Start() {
  DCHECK(handle_.is_null());
  CHECK(base::PlatformThread::Create(0, this, &handle_));
}

void Story::PlotLineRunner::Join() {
  DCHECK(!handle_.is_null());
  base::PlatformThread::Join(handle_);
}

void Story::PlotLineRunner::RunImpl() {
  for (size_t i = 0; i < plot_line_->size(); ++i) {
    auto evt = (*plot_line_)[i];
    if (!evt->Play(backdrop_)) {
      failed_event_ = evt;
      return;
    }
  }
}

}  // namespace bard

bool operator==(const bard::Story::PlotLine& pl1,
                const bard::Story::PlotLine& pl2) {
  if (pl1.size() != pl2.size())
    return false;
  for (size_t i = 0; i < pl1.size(); ++i) {
    if (!pl1[i]->Equals(pl2[i]))
      return false;
  }
  return true;
}
