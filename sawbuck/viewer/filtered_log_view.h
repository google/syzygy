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
// Filtered list view declaration.
#ifndef SAWBUCK_VIEWER_FILTERED_LOG_VIEW_H_
#define SAWBUCK_VIEWER_FILTERED_LOG_VIEW_H_

#include <map>
#include <string>
#include <vector>

#include "base/scoped_ptr.h"
#include "sawbuck/viewer/filter.h"
#include "sawbuck/viewer/log_list_view.h"

// Forward decl.
class CancelableTask;

// Provides a filtered view on a log.
class FilteredLogView
    : public ILogViewEvents,
      public ILogView {
 public:
  explicit FilteredLogView(ILogView* original,
                           const std::vector<Filter>& filters);
  ~FilteredLogView();

  // ILogViewEvents implementation.
  virtual void LogViewNewItems();
  virtual void LogViewCleared();

  // ILogView implementation;
  // @{
  virtual int GetNumRows();
  virtual void ClearAll();
  virtual int GetSeverity(int row);
  virtual DWORD GetProcessId(int row);
  virtual DWORD GetThreadId(int row);
  virtual base::Time GetTime(int row);
  virtual std::string GetFileName(int row);
  virtual int GetLine(int row);
  virtual std::string GetMessage(int row);
  virtual void GetStackTrace(int row, std::vector<void*>* trace);
  virtual void Register(ILogViewEvents* event_sink,
                        int* registration_cookie);
  virtual void Unregister(int registration_cookie);
  // @}

 void SetFilters(const std::vector<Filter>& filters);

 protected:
  void PostFilteringTask();
  void FilterChunk();
  virtual void RestartFiltering();

  // Returns true if the item at |index| would match a filter in |list|,
  // false otherwise.
  bool MatchesFilterList(const std::vector<Filter>& list, int index);

  // The filters we are using. We break them into two lists, one that contains
  // inclusion filters, the other exclusion filters.
  std::vector<Filter> inclusion_filters_;
  std::vector<Filter> exclusion_filters_;

  // The included rows we have filtered.
  std::vector<int> included_rows_;
  // Row number of last row in |original_| that we've processed.
  int filtered_rows_;
  // Non-NULL if there's a task pending to process additional rows.
  CancelableTask* task_;

  ILogView* original_;
  int registration_cookie_;

  typedef std::map<int, ILogViewEvents*> EventSinkMap;
  EventSinkMap event_sinks_;
  int next_sink_cookie_;

  DISALLOW_COPY_AND_ASSIGN(FilteredLogView);
};

#endif  // SAWBUCK_VIEWER_FILTERED_LOG_VIEW_H_
