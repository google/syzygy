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
// Class encapsulating extraction and listing basic info on configuration.
#ifndef SAWDUST_TRACER_SYSTEM_INFO_H_
#define SAWDUST_TRACER_SYSTEM_INFO_H_

#include <sstream>
#include <string>

#include "sawdust/tracer/upload.h"

// Extracts some basic information on the current system: operating system name
// and version, processor type (and other things provided by GetSystemInfo),
// list of environment variables. All that packaged as a stream.
class SystemInfoExtractor : public IReportContentEntry {
 public:
  SystemInfoExtractor() { }
  virtual ~SystemInfoExtractor() {}

  // Initialize the object. The stream (data()) can be read once initialized.
  // Appending env-vars is optional (|include_env_variables|).
  virtual void Initialize(bool include_env_variables);

  std::istream& Data() { return data_as_stream_; }
  void MarkCompleted() { data_as_stream_.seekg(0); }

  const char* Title() const { return "BasicSystemInformation.txt"; }

  // Reformats |string_table| (output of GetEnvironmentStrings call) and
  // formats this nicely into a \n separated list of values in |out_string|.
  static void ListEnvironmentStrings(const wchar_t* string_table,
                                     std::string* out_string);
 protected:
  // Real datatype under data(). Added as a test seam.
  typedef std::istringstream StreamType;

  static const char kHeaderMem[];
  static const char kHeaderSysName[];
  static const char kHeaderSysInfo[];
  static const char kHeaderSysInfo2[];
  static const char kHeaderPageSize[];
  static const char kHeaderProcs[];
  static const char kHeaderProcRev[];
  static const char kHeaderProcMask[];

  // Format nicely the content of |data|.
  static void FromSystemInfo(const SYSTEM_INFO& data, std::string* out_string);

 private:
  // Exposed to create a test seam.
  virtual void AppendEnvironmentStrings(std::string* out_string);
  StreamType data_as_stream_;

  DISALLOW_COPY_AND_ASSIGN(SystemInfoExtractor);
};

#endif  // SAWDUST_TRACER_SYSTEM_INFO_H_
