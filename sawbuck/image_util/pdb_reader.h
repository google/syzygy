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
#ifndef SAWBUCK_IMAGE_UTIL_PDB_READER_H_
#define SAWBUCK_IMAGE_UTIL_PDB_READER_H_

#include <iostream>
#include "base/file_path.h"
#include "sawbuck/image_util/pdb_stream.h"

// This class is used to read a pdb file and load its streams into memory.
// It is able to parse the pdb header and directory data, but only the stream
// data is available outside the class.
// TODO(ericdingle): This can be memory intensive for large pdb files. We should
// allow for streams to be created that refer to an open file and be able to
// read the stream data from there. This would include having some properties
// from the header (e.g. page_size) as class members.
class PdbReader {
 public:
  PdbReader();
  ~PdbReader();

  // Read a pdb file into memory. pdb_path is the file path relative to the
  // current working directory, and pdb_streams is a pointer to an already
  // instantiated PdbStreamList which will contain a list of PdbStreams on
  // a successful file read.
  bool Read(const FilePath& pdb_path, PdbStreamList* pdb_streams);

 private:
  // Multi-Stream Format (MSF) Header
  // See http://code.google.com/p/pdbparser/wiki/MSF_Format
  struct PdbFileHeader {
    uint8 magic_string[32];
    uint32 page_size;
    uint32 free_page_map;
    uint32 num_pages;
    uint32 directory_size;
    uint32 reserved;
    uint32 root_pages[73];
  };

  // Get the file size in bytes for an already opened file handle.
  // Will set stream cursor to end of file.
  bool GetFileSize(FILE* file, uint32* size);

  // Read a given page from file into the destination buffer.
  bool ReadBytesFromPage(void* dest,
                         FILE* file,
                         uint32 num_bytes,
                         uint32 page_num,
                         uint32 page_size);

  // Get the number of pages required to store specified number of bytes.
  uint32 GetNumPages(uint32 num_bytes, uint32 page_size);

  // Load a stream into memory.
  bool LoadStream(void* dest,
                  FILE* file,
                  uint32 num_bytes,
                  const uint32* const pages,
                  uint32 page_size);
};

#endif  // SAWBUCK_IMAGE_UTIL_PDB_READER_H_
