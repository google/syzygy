// Copyright 2013 Google Inc. All Rights Reserved.
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
// Declares ImageFilter, a structure for imposing a filter on an image. The
// filter itself is a core::AddressFilter built on relative addresses.

#ifndef SYZYGY_PE_IMAGE_FILTER_H_
#define SYZYGY_PE_IMAGE_FILTER_H_

#include "base/values.h"
#include "base/files/file_path.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_filter.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

struct ImageFilter {
  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressFilter<RelativeAddress, size_t> RelativeAddressFilter;
  typedef RelativeAddressFilter::Range Range;

  // The signature of the module to which this filter applies.
  PEFile::Signature signature;

  // The filtered relative address space.
  RelativeAddressFilter filter;

  // Initializes this ImageFilter to the given PE file. Sets the signature,
  // the extent of the filter, and clears the marked ranges.
  // @param pe_signature The signature to use.
  // @param pe_file The module whose signature should be used.
  // @param path The path to the module whose signature should be used.
  // @returns true on success, false otherwise.
  void Init(const PEFile::Signature& pe_signature);
  void Init(const PEFile& pe_file);
  bool Init(const base::FilePath& path);

  // Determines if this filter is for the given module.
  // @param pe_signature The signature to compare against.
  // @param pe_file The module to compare against.
  // @param path The path to the module to compare against.
  // @returns true if this filter matches the provided module, false otherwise.
  bool IsForModule(const PEFile::Signature& pe_signature) const;
  bool IsForModule(const PEFile& pe_file) const;
  bool IsForModule(const base::FilePath& path) const;

  // Saves this image filter to file.
  // @param json The JSON writer to be written to.
  // @param pretty_print If true the file will be pretty-printed.
  // @param file The file to be written to.
  // @param path The path of the file to be written to.
  // @returns true on success, false otherwise.
  // @note Logs on error.
  bool SaveToJSON(core::JSONFileWriter* json) const;
  bool SaveToJSON(bool pretty_print, FILE* file) const;
  bool SaveToJSON(bool pretty_print, const base::FilePath& path) const;

  // Loads an image filter from a file in JSON format.
  // @param dict The JSON dictionary to be loaded from.
  // @param file The file to be read from.
  // @param path The path of the file to be read.
  // @returns true on success, false otherwise.
  // @note Logs on error.
  bool LoadFromJSON(const base::DictionaryValue& dict);
  bool LoadFromJSON(FILE* file);
  bool LoadFromJSON(const base::FilePath& path);
};

}  // namespace pe

#endif  // SYZYGY_PE_IMAGE_FILTER_H_
