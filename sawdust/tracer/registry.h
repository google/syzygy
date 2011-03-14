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
// Class encapsulating extraction of registry information.
#ifndef SAWDUST_TRACER_REGISTRY_H_
#define SAWDUST_TRACER_REGISTRY_H_

#include <iostream>  // NOLINT - streams used as abstracts, without formatting.
#include <list>
#include <string>
#include <vector>

#include "base/win/registry.h"

#include "sawdust/tracer/configuration.h"
#include "sawdust/tracer/upload.h"

// Dumps selection of the system registry's content as an UTF-8 encoded text
// stream. That selection is defined by a vector of registry path passed to
// Initialize (see comment there).
// File format (for key query)
// HK??\\Level1\\...\\Key
// <tab>Subkey1
// <tab><tab>ValueName<tab>formatted value
// <tab>Subkey2
// <tab><tab>SubkeySubkey1
// <tab><tab><tab>ValueName<tab>ValueValue
// <tab>Subkey3
// <tab>ValueName<tab>Value
// For value path:
// HK??\\Level1\\...\\Key\\ValueName<tab>ValueValue
// If a value is a multi-line string, it will be displayed in multiple lines
// with indentation matching the value in the first line.
// In short, the format presents a tree in depth-first order. The node order is
// as defined in registry (valued first). Indentation is marked by \t symbol,
// which also separates value names from data stored there. Integral values are
// shown as hex, binary data as byte-wide hex.
class RegistryExtractor : public IReportContentEntry {
 public:
  RegistryExtractor();
  virtual ~RegistryExtractor() {}

  // Normal initialize function. Since reading / writing is done through own
  // streambuf, all we do on initialization is to collect input entries and make
  // sure they all are accessible.
  // Also, the function will disregard nested folders by doing simple string
  // comparisons. Last (but not least), an entry can be a registry folder
  // (which will be recursed) or a value.
  int Initialize(const std::vector<std::wstring>& input_container);

  std::istream& data();
  void MarkCompleted();

  const char* title() const { return "RegistryExtract.txt"; }

  // Formats the content of the buffer with a REG_MULTI_SZ value (double-null
  // terminated array of null-terminated strings) into \n separated utf8 string.
  // Each line starting second is indented by |indent| \t. New data is appended
  // to |formatted_utf8|.
  static bool FormatMultiStringValue(const wchar_t* buffer, size_t buf_length,
                                     int indent, std::string* formatted_utf8);
  // Formats binary data as hex (each byte to two characters, as by sprintf,
  // space separated).
  static bool FormatBinaryValue(const char* buffer, size_t buffer_size,
                                std::string* formatted_output);
  // Formats nicely a value named |value_name| stored in the registry |key|.
  // If the output takes up more than one line, each line starting from second
  // will be indented by |multiline_indent| \t. New data is appended
  // to |formatted_utf8|.
  static bool CreateFormattedRegValue(base::win::RegKey* key,
                                      const wchar_t* value_name,
                                      int multiline_indent,
                                      std::string* formatted_utf8);
 protected:
  // A structure holding information about a registry key or value.
  // It is a value if |value_name_| is not empty.
  struct ScanEntryDef {
    HKEY root_;
    std::string root_name_;
    std::wstring path_;
    std::wstring value_name_;

    unsigned indent_;

    ScanEntryDef() : root_(NULL), indent_(0) {
    }
  };

  typedef std::list<ScanEntryDef> EntriesCollection;

  void Reset();

  // Given a registry path (HKEYs as strings), populate |entry|. Accesses
  // actual registry to make sure the path exists. Note that |full_path| may
  // point either to a key
  static bool VerifiedEntryFromString(const std::wstring& full_path,
                                      ScanEntryDef* entry);

 private:
  class RegistryStreamBuff;

  EntriesCollection validated_root_entries_;
  std::vector<std::wstring> missing_entries_;

  std::istream own_data_stream_;

  scoped_ptr<std::streambuf> current_streambuff_;

  DISALLOW_COPY_AND_ASSIGN(RegistryExtractor);
};

#endif  // SAWDUST_TRACER_REGISTRY_H_
