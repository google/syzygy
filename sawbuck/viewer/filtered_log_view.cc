// Copyright 2010 Google Inc.
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
// Filtered list view implementation.
#include "sawbuck/viewer/filtered_log_view.h"

#include "base/bind.h"
#include "base/logging.h"
#include "pcrecpp.h"  // NOLINT

FilteredLogView::FilteredLogView(ILogView* original,
                                 const std::vector<Filter>& filters) :
    filtered_rows_(0), original_(original),
    registration_cookie_(0), next_sink_cookie_(1) {
  DCHECK(original_ != NULL);
  original_->Register(this, &registration_cookie_);
  SetFilters(filters);
}

FilteredLogView::~FilteredLogView() {
  // Make sure we're not pinged post-destruction.
  if (!task_.IsCancelled())
    task_.Cancel();

  original_->Unregister(registration_cookie_);
}

void FilteredLogView::LogViewNewItems() {
  PostFilteringTask();
}

void FilteredLogView::LogViewCleared() {
  RestartFiltering();
  EventSinkMap::iterator it(event_sinks_.begin());
  for (; it != event_sinks_.end(); ++it)
    it->second->LogViewCleared();
}

int FilteredLogView::GetNumRows() {
  return included_rows_.size();
}

void FilteredLogView::ClearAll() {
  original_->ClearAll();
}

int FilteredLogView::GetSeverity(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetSeverity(included_rows_[row]);
}

DWORD FilteredLogView::GetProcessId(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetProcessId(included_rows_[row]);
}

DWORD FilteredLogView::GetThreadId(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetThreadId(included_rows_[row]);
}

base::Time FilteredLogView::GetTime(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetTime(included_rows_[row]);
}

std::string FilteredLogView::GetFileName(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetFileName(included_rows_[row]);
}

int FilteredLogView::GetLine(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetLine(included_rows_[row]);
}

std::string FilteredLogView::GetMessage(int row) {
  DCHECK(row < GetNumRows());

  return original_->GetMessage(included_rows_[row]);
}

void FilteredLogView::GetStackTrace(int row, std::vector<void*>* trace) {
  DCHECK(row < GetNumRows());

  return original_->GetStackTrace(included_rows_[row], trace);
}

void FilteredLogView::Register(ILogViewEvents* event_sink,
                            int* registration_cookie) {
  int cookie = next_sink_cookie_++;

  event_sinks_.insert(std::make_pair(cookie, event_sink));
  *registration_cookie = cookie;
}

void FilteredLogView::Unregister(int registration_cookie) {
  event_sinks_.erase(registration_cookie);
}

bool FilteredLogView::MatchesFilterList(const std::vector<Filter>& list,
                                        int index) {
  std::vector<Filter>::const_iterator iter(list.begin());
  for (; iter != list.end(); ++iter) {
    if (iter->Matches(original_, index)) {
      return true;
    }
  }
  return false;
}

void FilteredLogView::FilterChunk() {
  task_.Cancel();

  // Stash our starting row count.
  int starting_rows = GetNumRows();

  // Figure the range we're going to filter.
  const int kMaxFilterRows = 1000;
  int start = filtered_rows_;
  int end = std::min(filtered_rows_ + kMaxFilterRows, original_->GetNumRows());


  if (inclusion_filters_.empty()) {
    // If the inclusion_filters_ list is empty, show all rows that do not match
    // a filter in the exclusion list
    for (int i = start; i < end; ++i) {
      // Run the exclusion filters here..
      if (!MatchesFilterList(exclusion_filters_, i)) {
        included_rows_.push_back(i);
      }
    }
  } else {
    // Otherwise, show all rows that match a filter in the inclusion list but
    // match no rows in the exclusion list.
    for (int i = start; i < end; ++i) {
      if (MatchesFilterList(inclusion_filters_, i) &&
          !MatchesFilterList(exclusion_filters_, i)) {
        included_rows_.push_back(i);
      }
    }
  }

  // Update our cursor.
  filtered_rows_ = end;

  // Post again if we're not done.
  if (end != original_->GetNumRows())
    PostFilteringTask();

  // If we added rows, signal the change.
  if (starting_rows != GetNumRows()) {
    EventSinkMap::iterator it(event_sinks_.begin());
    for (; it != event_sinks_.end(); ++it)
      it->second->LogViewNewItems();
  }
}

void FilteredLogView::SetFilters(const std::vector<Filter>& filters) {
  inclusion_filters_.clear();
  exclusion_filters_.clear();

  std::vector<Filter>::const_iterator iter(filters.begin());
  for (; iter != filters.end(); ++iter) {
    if (iter->action() == Filter::INCLUDE) {
      inclusion_filters_.push_back(*iter);
    } else if (iter->action() == Filter::EXCLUDE) {
      exclusion_filters_.push_back(*iter);
    } else {
      NOTREACHED();
    }
  }

  RestartFiltering();
}

void FilteredLogView::RestartFiltering() {
  // Reset our included state and our filtering state.
  filtered_rows_ = 0;
  included_rows_.clear();
  PostFilteringTask();
}

void FilteredLogView::PostFilteringTask() {
  if (task_.IsCancelled()) {
    task_.Reset(base::Bind(&FilteredLogView::FilterChunk,
                           base::Unretained(this)));
    base::MessageLoop::current()->PostTask(FROM_HERE, task_.callback());
  }
}
