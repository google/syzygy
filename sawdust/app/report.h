// Copyright 2011 Google Inc.
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
// Construct a 'report' (content to be uploaded) from acquired data.
#ifndef SAWDUST_APP_REPORT_H_
#define SAWDUST_APP_REPORT_H_

#include <list>

#include "base/scoped_ptr.h"

#include "sawdust/tracer/configuration.h"
#include "sawdust/tracer/controller.h"
#include "sawdust/tracer/registry.h"
#include "sawdust/tracer/system_info.h"
#include "sawdust/tracer/upload.h"

// The class serves all uploadable content, wrapping log files into own
// specialization of IReportContentEntry. It will also include system info and
// registry extraction if declared so in configuration.
class ReportContent : public IReportContent {
 public:
  ReportContent() {}
  ~ReportContent();

  // Creates all required wrappers and extractors, as defined by |config|. Log
  // files will be dug out from |controller|.
  HRESULT Initialize(const TracerController& controller,
                     const TracerConfiguration& config);

  HRESULT GetNextEntry(IReportContentEntry** entry);


  class ReportEntryWithInit : public IReportContentEntry {
   public:
    virtual HRESULT Initialize() = 0;
  };

 private:
  // Factory functions added as test seams.
  virtual SystemInfoExtractor* CreateInfoExtractor() {
    return new SystemInfoExtractor();
  }

  virtual RegistryExtractor* CreateRegistryExtractor() {
    return new RegistryExtractor();
  }

  typedef std::list<ReportEntryWithInit*> ReportEntryContainer;
  ReportEntryContainer entry_queue_;
  scoped_ptr<ReportEntryWithInit> current_entry_;
};

#endif  // SAWDUST_APP_REPORT_H_
