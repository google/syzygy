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
// Declares a class for holding file and line information as extracted from a
// PDB.

#ifndef SYZYGY_GRINDER_LINE_INFO_H_
#define SYZYGY_GRINDER_LINE_INFO_H_

#include "base/files/file_path.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"

namespace grinder {

// Holds line information extracted from a PDB. This object holds information
// on multiple files, and each file holds information in an address space for
// efficient lookup by code address.
//
// NOTE: This does not handle 'partial' line coverage right now. It is possible
//     for only some of the code bytes associated with a line to have been
//     visited. We need finer grained bookkeeping to accommodate this (the
//     LCOV file format can handle it just fine). The MSVC tools do not seem to
//     make a distinction between partially and fully covered lines.
//
// TODO(chrisha): Make a more efficient sorted-collection-based version of
//     Visit. This can be O(N) rather than O(N log N) and would be useful with
//     the coverage grinder.
class LineInfo {
 public:
  struct SourceLine;  // Forward declaration.
  typedef std::set<std::string> SourceFileSet;
  typedef std::vector<SourceLine> SourceLines;

  // Initializes this LineInfo object with data read from the provided PDB.
  // @param pdb_path the PDB whose line information is to be read.
  // @returns true on success, false otherwise.
  bool Init(const base::FilePath& pdb_path);

  // Visits the given address range. A partial visit of the code associated
  // with a line is considered as a visit of that line.
  // @param address the starting address of the address range.
  // @param size the size of the address range to visit.
  // @param the number of times to visit this line.
  bool Visit(core::RelativeAddress address, size_t size, size_t count);

  // @name Accessors.
  // @{
  const SourceFileSet& source_files() const { return source_files_; }
  const SourceLines& source_lines() const { return source_lines_; }
  // @}

 protected:
  // Used to store unique file names in a manner such that we can draw stable
  // pointers to them. The SourceLine objects will point to the strings in this
  // set.
  SourceFileSet source_files_;

  // Source line information is stored here sorted by order of address, which is
  // the order in which we retrieve it from the PDB. This lets us do efficient
  // binary search lookups in Visit.
  SourceLines source_lines_;
};

// Describes a single line of source code from some file.
struct LineInfo::SourceLine {
  SourceLine(const std::string* source_file_name,
             size_t line_number,
             core::RelativeAddress address,
             size_t size)
      : source_file_name(source_file_name),
        line_number(line_number),
        address(address),
        size(size),
        visit_count(0) {
  }

  // Points to the source file in which this line is found.
  const std::string* source_file_name;
  size_t line_number;
  // The address in the image corresponding to the line.
  core::RelativeAddress address;
  // The size may be zero if there are multiple lines mapping to a single
  // basic-block. This can happen during optimizations, etc.
  size_t size;
  // Indicates the number of visits to this line. A value of zero indicates
  // that the line is instrumented, but has not been visited.
  uint32 visit_count;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_LINE_INFO_H_
