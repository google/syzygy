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
// Declares a class for writing an archive of COFF object files to a .lib
// file. See ar_reader.h for details of MSVS version of the file format.

#ifndef SYZYGY_AR_AR_WRITER_H_
#define SYZYGY_AR_AR_WRITER_H_

#include <set>

#include "base/files/file_path.h"
#include "base/memory/scoped_vector.h"
#include "syzygy/ar/ar_common.h"

namespace ar {

// Class for writing an archive of COFF object files. This mimics the behaviour
// of lib.exe in that duplicate symbol definitions are ignored but allowed, with
// the first definition being the one that is exported to the symbol table.
class ArWriter {
 public:
  typedef std::pair<ParsedArFileHeader, const DataBuffer*> File;
  typedef std::vector<File> FileVector;

  ArWriter();

  // @returns the current list of files that will be added to the archive.
  const FileVector& files() const { return files_; }

  // @returns the current set of exported symbols.
  const SymbolIndexMap& symbols() const { return symbols_; }

  // Schedules the given object file to be added to the archive.
  // @param filename The filename that will be associated with the content.
  // @param timestamp The timestamp to be associated with the file.
  // @param mode The mode to be associated with the file. In the same format
  //     as ST_MODE from _wstat.
  // @param contents The contents of the file. The lifetime of this object
  //     must exceed the lifetime of the writer.
  // @param path The file to be added; the filename as specified in @p path
  //     will be used, and the contents read from disk. Uses the timestamp and
  //     mode of the file on disk.
  // @returns true on success, false otherwise.
  bool AddFile(const base::StringPiece& filename,
               const base::Time& timestamp,
               uint32 mode,
               const DataBuffer* contents);
  bool AddFile(const base::FilePath& path);

  // Writes the current set of files to an archive at the specified @p path.
  // @param path The path of the archive file to be written.
  // @returns true on success, false otherwise.
  bool Write(const base::FilePath& path);

 protected:
  typedef std::set<std::pair<std::string, size_t>> FileIndexMap;
  typedef ScopedVector<DataBuffer> ScopedDataBuffers;

  // Contains a collection of object files and the names with which they
  // will be committed to the archive.
  FileVector files_;

  // A multimap of filenames to their indices in |files_|.
  FileIndexMap file_index_map_;

  // Any files whose contents have been read by the writer are stored here.
  ScopedDataBuffers buffers_;

  // The collection of symbols exported from the various object files.
  SymbolIndexMap symbols_;

  // The collection of weak symbols currently exported from the various object
  // files. These have to be tracked separately as they can be overridden by
  // later object files.
  SymbolIndexMap weak_symbols_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ArWriter);
};

}  // namespace ar

#endif  // SYZYGY_AR_AR_WRITER_H_
