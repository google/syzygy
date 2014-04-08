// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declares a class for reading/extracting files from a lib file in the 'ar'
// achive format.
//
// A MSVS library file uses the standard archive file format that is used
// by most toolchains everywhere. More specifically it observes the same format
// as the GNU variant, with seem extensions. The format is well documented here:
//
//   http://kishorekumar.net/pecoff_v8.1.htm
//
// The archive contains three special metadata files, occurring as the three
// files in the archive.
//
//   "/" : This file contains a concatenation of all symbol information
//         across all object files in the library. This is divided into
//         3 parts:
//         - a big-endian 32-bit integer encoding the number of symbols.
//         - big-endian 32-bit integers encoding the offset in the archive
//           of the file containing the symbol. This must be in increasing
//           order.
//         - a concatenation of null-terminated ASCII-encoded symbol
//           names. These are implicitly ordered due to the ordering of the
//           offsets.
//         This table only ends up pointing to object files that actually
//         contain symbols, this can undercount the true number of files in
//         the archive. This is present for backwards compatibility with
//         older linkers (and the GCC format), but is not actively used by
//         MSVS.
//   "/" : If a second file with the name "/" is present this is a MSVS
//         custom table that encodes the number of files in the archive, and
//         their absolute locations.
//         - a little endian 32-bit integer indicating the number of object
//           files in the archive. This includes object files that do not
//           contain symbols.
//         - little-endian 32-bit integers encoding the offset in the archive
//           of the file containing the symbol.
//         - a little-endian 32-bit integer encoding the number of symbols.
//         - a run of little-endian 16-bit integers indicating the file in
//           which the symbol is located (1 indexed).
//         - a concatenation of null-terminated ASCII-encoded symbol
//           names. These are in increasing lexical order.
//   "//": This file contains extended filenames of all object files in the
//         library. These are simply a concatenation of null-terminated
//         ASCII-encoded filenames. This has been observed to always be in
//         the same order as the files in the archive itself.
//         NOTE: This file does not always have the name '//', sometimes
//               appearing as a 3rd '/' table.
//
// All of the above mentioned special files must exist in the archive, and must
// be the first 3 files.
//
// The actual object files are stored with names like "/<some-number>".
// Their true full path names are available at offset <some-number> in the "//"
// extended path name stream. These have been observed to be in strictly
// increasing order, with the filenames themselves in no particular order.

#ifndef SYZYGY_AR_AR_READER_H_
#define SYZYGY_AR_AR_READER_H_

#include <map>
#include <vector>

#include "base/file_util.h"
#include "base/files/file_path.h"
#include "syzygy/ar/ar_common.h"

namespace ar {

// Class for extracting files from archive files. This currently does not
// expose the parsed symbol information in any meaningful way.
class ArReader {
 public:
  // Maps symbols by their name to the index of the archived file containing
  // them.
  typedef std::map<std::string, uint32> SymbolIndexMap;
  // Stores the offsets of each file object, by their index.
  typedef std::vector<uint32> FileOffsetVector;
  // Maps sorted object filenames to their index in the archive.
  typedef std::map<std::string, size_t> FileNameMap;
  // Stores filenames indexed by the file number.
  typedef std::vector<std::string> FileNameVector;

  ArReader();

  // Opens the provided file, validating that it is indeed an archive file,
  // parsing its headers and populating symbol and filename information. Logs
  // verbosely on failure.
  // @param ar_path The path to the file to be opened.
  // @returns true on success, false otherwise.
  bool Init(const base::FilePath& ar_path);

  // Determines the full names of all files in the archive, populating the
  // file-name map. This must be called in order to find a file by name. This
  // incurs a linear scan of the entire archive.
  // @returns true on success, false otherwise.
  // @note Can only be called after a successful call to Init. This should only
  //     be called once.
  bool BuildFileIndex();

  // @returns the path of the file being read.
  const base::FilePath& path() const { return path_; }

  // @returns the map of symbols contained in the various object files in the
  //     archive. The symbol name is mapped to the index of the object file
  //     containing it.
  const SymbolIndexMap& symbols() const { return symbols_; }

  // @returns the offsets of files in the archive. This is only valid after a
  //     successful call to Init.
  const FileOffsetVector& offsets() const { return offsets_; }

  // @returns the vector of file names, by their index in the archive.
  //     This is only valid after a successful call to BuildFileIndex.
  const FileNameVector& files() const { return files_; }

  // @returns the map of files present in the archive, and their
  //     indices within it. This is only valid after a successful call to
  //     BuildFileIndex.
  const FileNameMap& files_inverse() const { return files_inverse_; }

  // Seeks to the beginning of the archived files. Allows repeated iteration.
  // @returns true on success, false otherwise.
  bool SeekStart();

  // @returns true if there is a next file in the archive to extract.
  bool HasNext() const;

  // Extracts the next file to a buffer, and advances the cursor to
  // the next file in the archive.
  // @param header The header to be populated.
  // @param data The buffer to be populated. May be NULL, in which case
  //     only the header will be filled in.
  // @returns true on success, false otherwise.
  bool ExtractNext(ParsedArFileHeader* header, DataBuffer* data);

  // Extracts the specified file to a buffer. Leaves the cursor pointing
  // at the next file in the archive.
  // @param index The index of the file to be extracted.
  // @param header The header to be populated.
  // @param data The buffer to be populated.
  // @returns true on success, false otherwise.
  bool Extract(size_t index,
               ParsedArFileHeader* header,
               DataBuffer* data);

 protected:
  // Reads the next file from the archive, advancing the cursor. Returns true
  // on success, false otherwise. Does not translate the internal name to an
  // external filename.
  bool ReadNextFile(ParsedArFileHeader* header, DataBuffer* data);

  // Translates an archive internal filename to the full extended filename.
  bool TranslateFilename(const std::string& internal_name,
                         std::string* full_name);

  // The file that is being read.
  base::FilePath path_;
  file_util::ScopedFILE file_;

  // Data regarding the archive.
  uint64 length_;
  uint64 offset_;
  uint64 start_of_object_files_;

  // Parsed header information.
  SymbolIndexMap symbols_;
  FileOffsetVector offsets_;
  // The raw file names, concatenated into a single buffer.
  DataBuffer filenames_;
  // Maps filenames to their indices in the archive. This is populated by
  // BuildFileIndex.
  FileNameVector files_;
  FileNameMap files_inverse_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ArReader);
};

}  // namespace ar

#endif  // SYZYGY_AR_AR_READER_H_
