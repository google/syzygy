// Copyright 2012 Google Inc. All Rights Reserved.
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
// Implements an experimental command line tool that tallies the amount
// of object code contributed to an executable by source line.

#ifndef SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_H_
#define SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_H_

#include <dia2.h>
#include <cstdio>
#include <map>
#include <vector>

#include "base/callback.h"
#include "base/file_version_info.h"
#include "base/files/file_path.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/core/address_space.h"
#include "syzygy/pe/pe_file.h"

// Fwd.
namespace core {
class JSONFileWriter;
}  // namespace core

// A worker class that attributes the code generated for each function back
// to the source lines that contributed it.
//
// The output generated is a JSON file expressing this hierarchy:
// - Object File
//   - Function
//     - Source Contribution
//
// Since the amount of output data for a large binary like Chrome.dll is large,
// the JSON output is condensed by outputting source file names in a single
// table, then referring to source file names by their index in the table.
//
// As an example, consider this example:
// --- bar.h --
// 01:  // A sample header.
// 02:
// 03: inline inline_function() {
// 04:   ...
// 05:   ...
// 06: }
// --- bar.h --
//
// --- foo.cc --
// 01: #include "bar.h"
// 02:
// 03: void function() {
// 04:   inline_function();
// 05: }
// --- foo.cc --
//
// For which we'll get JSON output like this:
//
// --- output ---
//
// {
//   "executable": {
//     // The name of the image file.
//     "name": "foo.exe",
//     // The image file's version.
//     "version": "1.2.3.4",
//     // The image file's date/time stamp.
//     "timestamp": "0x54F2F851083562"
//   },
//   "sources": [
//     "bar.h",
//     "foo.cc",
//   ],
//   "objects": {
//     "foo.obj": {
//       "function": {
//         "size": 17.0,
//         "contribs": [
//           0,  // Zero-based index of "bar.h" in sources.
//           [
//             3, 6.5,  // 6.5 bytes contributed by line 3 of bar.h.
//           ]
//           1,  // Zero-based index of "foo.cc" in sources.
//           [
//             3, 19,  // 19 bytes contributed by line 3 of foo.cc.
//             5, 12,  // 12 bytes contributed by line 12 of foo.cc.
//           ],
//         ],
//       },
//     },
//   }
// }
// --- output ---
//
// The accounting is complicated by code sharing, which means to do an accurate
// tally, we have to account for fractional bytes. As a case in point, a
// template function may expand to identical code for multiple types, but the
// linker may then fold all the identical template expansions to a single,
// canonical function.
// We therefore have to iterate through the source lines twice:
// - On the first pass we update the use counts for each byte referenced from
//   source line contribution.
// - On the second pass we know how often each code byte is shared, and so
//   we can accrue the correct tally.
class CodeTally {
 public:
  // Creates a code tally instance for the given image file.
  explicit CodeTally(const base::FilePath& image_file);

  // Crawls the PDB file and updates internal state with code contribution
  // down to function, source line per object file.
  bool TallyLines(const base::FilePath& pdb_file);

  // Generates a JSON file from the internal state.
  bool GenerateJsonOutput(core::JSONFileWriter* writer);

 private:
  struct LineInfo;
  struct FunctionInfo;
  struct ObjectFileInfo;
  struct SourceFileInfo;

  typedef std::map<std::wstring, SourceFileInfo> SourceFileInfoMap;
  typedef std::map<std::wstring, ObjectFileInfo> ObjectFileInfoMap;

  typedef core::AddressSpace<size_t, size_t, FunctionInfo>
      FunctionInfoAddressSpace;
  typedef FunctionInfoAddressSpace::Range FunctionRange;

  SourceFileInfo* FindOrCreateSourceFileInfo(const wchar_t* source_file);
  ObjectFileInfo* FindOrCreateObjectFileInfo(const wchar_t* object_file);

  // Increases the use count for bytes [start, start + len) by one.
  void UseRange(size_t start, size_t len);

  // Sums up the total code contribution by the bytes in [start, start + len).
  double CalculateByteContribution(size_t start, size_t len);

  // Callbacks for compiland enumeration.
  bool OnCompilandPassOne(IDiaSymbol* compiland);
  bool OnCompilandPassTwo(IDiaSymbol* compiland);

  // Callback for line enumeration.
  // First pass only updates all use counts.
  bool OnLinePassOne(IDiaLineNumber* line_number);

  // Callback for Function enumeration.
  bool OnFunction(ObjectFileInfo* object_file, IDiaSymbol* function);

  // The second pass can accurately tally code contribution as
  // the first pass has calculated the sharing (use) count of
  // each byte in the binary.
  bool OnLinePassTwo(ObjectFileInfo* object_file, IDiaLineNumber* line_number);

  // The image file we work on.
  base::FilePath image_file_;

  // The signature of image_file_, valid after a successful call to
  // TallyLines.
  pe::PEFile::Signature image_signature_;

  // The file version for image_file_, valid after a successful call to
  // TallyLines.
  std::unique_ptr<FileVersionInfo> image_file_version_;

  // The DIA session this instance works with.
  base::win::ScopedComPtr<IDiaSession> session_;

  // Maps from object file name to ObjectFileInfo.
  ObjectFileInfoMap object_files_;

  // Maps from source file name to SourceFileInfo.
  SourceFileInfoMap source_files_;

  // Keeps track of how many times each byte in Chrome.dll was referenced from
  // any source line.
  std::vector<size_t> use_counts_;

  DISALLOW_COPY_AND_ASSIGN(CodeTally);
};

// Data maintained per source line during tally.
struct CodeTally::LineInfo {
  // The number of times we encountered this line.
  size_t occurrences;
  // The total number of code bytes accrued to this line.
  double code_bytes;
};

// Data maintained per function in an object file during tally.
struct CodeTally::FunctionInfo {
  explicit FunctionInfo(const wchar_t* n) : name(n) {
  }

  // Name of this function.
  std::wstring name;

  // Data we keep for each line entry.
  struct LineData {
    CodeTally::SourceFileInfo* source_file;
    size_t offset;
    size_t line;
    double code_bytes;
  };

  // Line information records for this function.
  std::vector<LineData> line_info;
};

// Data maintained per object file during tally.
struct CodeTally::ObjectFileInfo {
  ObjectFileInfo() : file_name(NULL) {
  }

  // This object file's name.
  const wchar_t* file_name;

  // Keeps track of the functions in this object file.
  FunctionInfoAddressSpace functions;
};

// Data maintained per source file during tally.
struct CodeTally::SourceFileInfo {
  SourceFileInfo() : file_name(NULL) {
  }

  // This source file's name.
  const wchar_t* file_name;

  // The amount of code attributed to each line of this file.
  std::vector<CodeTally::LineInfo> line_code;
};

#endif  // SYZYGY_EXPERIMENTAL_CODE_TALLY_CODE_TALLY_H_
