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

#include "base/logging.h"
#include "pcrecpp.h"  // NOLINT

namespace {
// We only keep one outstanding task and we cancel it on destruction,
// so a noop retain is safe.
template <>
struct RunnableMethodTraits<FilteredLogView> {
  RunnableMethodTraits() {
  }

  ~RunnableMethodTraits() {
  }

  void RetainCallee(FilteredLogView* view) {
  }

  void ReleaseCallee(FilteredLogView* view) {
  }
};
}  // namespace

FilteredLogView::FilteredLogView(ILogView* original) : filtered_rows_(0),
    task_(NULL), original_(original), registration_cookie_(0),
    next_sink_cookie_(1) {
  DCHECK(original_ != NULL);
  original_->Register(this, &registration_cookie_);
  if (original_->GetNumRows() != 0)
    PostFilteringTask();
}

FilteredLogView::~FilteredLogView() {
  // Make sure we're not pinged post-destruction.
  if (task_ != NULL)
    task_->Cancel();

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

bool FilteredLogView::SetInclusionRegexp(const char* regexpr) {
  scoped_ptr<pcrecpp::RE> include(new pcrecpp::RE(regexpr, PCRE_UTF8));

  if (!include->error().empty())
    return false;

  include_re_.reset(include.release());

  RestartFiltering();

  return true;
}

bool FilteredLogView::SetExclusionRegexp(const char* regexpr) {
  scoped_ptr<pcrecpp::RE> exclude(new pcrecpp::RE(regexpr, PCRE_UTF8));

  if (!exclude->error().empty())
    return false;

  exclude_re_.reset(exclude.release());

  RestartFiltering();

  return true;
}

void FilteredLogView::FilterChunk() {
  task_ = NULL;

  // Stash our starting row count.
  int starting_rows = GetNumRows();

  // Figure the range we're going to filter.
  const int kMaxFilterRows = 1000;
  int start = filtered_rows_;
  int end = std::min(filtered_rows_ + kMaxFilterRows, original_->GetNumRows());

  for (int i = start; i < end; ++i) {
    std::string message(original_->GetMessage(i));
    if (include_re_ == NULL || include_re_->PartialMatch(message)) {
      if (exclude_re_ == NULL || !exclude_re_->PartialMatch(message))
        included_rows_.push_back(i);
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

void FilteredLogView::RestartFiltering() {
  // Reset our included state and our filtering state.
  filtered_rows_ = 0;
  included_rows_.clear();
  PostFilteringTask();
}

void FilteredLogView::PostFilteringTask() {
  if (!task_) {
    task_ = NewRunnableMethod(this, &FilteredLogView::FilterChunk);
    DCHECK(task_ != NULL);
    MessageLoop::current()->PostTask(FROM_HERE, task_);
  }
}
