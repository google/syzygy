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
#include "syzygy/pdb/pdb_reader.h"

#include "base/logging.h"
#include "base/string_util.h"
#include "syzygy/pdb/pdb_file_stream.h"

namespace pdb {

PdbReader::PdbReader() {
}

PdbReader::~PdbReader() {
  FreeStreams();
}

bool PdbReader::Read(const FilePath& pdb_path,
                     std::vector<PdbStream*>* streams) {
  FreeStreams();

  file_.reset(file_util::OpenFile(pdb_path, "rb"));
  if (!file_.get()) {
    LOG(ERROR) << "Unable to open '" << pdb_path.value() << "'";
    return false;
  }

  // Get the file size.
  uint32 file_size = 0;
  if (!GetFileSize(file_.get(), &file_size)) {
    LOG(ERROR) << "Unable to determine size of '" << pdb_path.value() << "'";
    return false;
  }

  // Read the header from the first page in the file.
  uint32 header_page = 0;
  PdbFileStream header_stream(file_.get(), sizeof(header_), &header_page,
                              kPdbPageSize);
  if (header_stream.Read(&header_, 1) != 1) {
    LOG(ERROR) << "Failed to read PDB file header";
    return false;
  }

  // Sanity checks.
  if (header_.num_pages * header_.page_size != file_size) {
    LOG(ERROR) << "Invalid PDB file size";
    return false;
  }

  if (memcmp(header_.magic_string, kPdbHeaderMagicString,
             sizeof(kPdbHeaderMagicString)) != 0) {
    LOG(ERROR) << "Invalid PDB magic string";
    return false;
  }

  // Load the directory page list (a sequence of uint32 page numbers that is
  // itself written across multiple root pages). To do this we need to know how
  // many pages are required to represent the directory, then we load a stream
  // containing that many page pointers from the root pages array.
  uint32 num_dir_pages = GetNumPages(header_.directory_size);
  PdbFileStream dir_page_stream(file_.get(), num_dir_pages * sizeof(uint32),
                                header_.root_pages, header_.page_size);
  scoped_array<uint32> dir_pages(new uint32[num_dir_pages]);
  if (dir_pages.get() == NULL) {
    LOG(ERROR) << "Failed to allocate directory pages";
    return false;
  }
  if (dir_page_stream.Read(dir_pages.get(), num_dir_pages)
      != num_dir_pages) {
    LOG(ERROR) << "Failed to read directory page stream";
    return false;
  }

  // Load the actual directory.
  uint32 dir_size = header_.directory_size / sizeof(uint32);
  PdbFileStream dir_stream(file_.get(), header_.directory_size,
                           dir_pages.get(), header_.page_size);
  directory_.reset(new uint32[dir_size]);
  if (directory_.get() == NULL) {
    LOG(ERROR) << "Failed to allocate directory";
    return false;
  }
  if (dir_stream.Read(directory_.get(), dir_size) != dir_size) {
    LOG(ERROR) << "Failed to read directory stream";
    return false;
  }

  // Iterate through the streams and construct PdbStreams.
  const uint32& num_streams = directory_[0];
  const uint32* stream_lengths = &(directory_[1]);
  const uint32* stream_pages = &(directory_[1 + num_streams]);

  uint32 page_index = 0;
  for (uint32 stream_index = 0; stream_index < num_streams; ++stream_index) {
    streams_.push_back(new PdbFileStream(file_.get(),
                                         stream_lengths[stream_index],
                                         stream_pages + page_index,
                                         header_.page_size));
    page_index += GetNumPages(stream_lengths[stream_index]);
  }

  *streams = streams_;
  return true;
}

bool PdbReader::GetFileSize(FILE* file, uint32* size) const {
  DCHECK(file != NULL);
  DCHECK(size != NULL);

  if (fseek(file, 0, SEEK_END) != 0) {
    LOG(ERROR) << "Failed seeking to end of file";
    return false;
  }

  long temp = ftell(file);
  if (temp == -1L) {
    LOG(ERROR) << "Failed to read stream position";
    return false;
  }

  (*size) = static_cast<uint32>(temp);
  return true;
}

uint32 PdbReader::GetNumPages(uint32 num_bytes) const {
  return (num_bytes + header_.page_size - 1) / header_.page_size;
}

void PdbReader::FreeStreams() {
  for (std::vector<PdbStream*>::const_iterator iter = streams_.begin();
       iter != streams_.end(); iter++) {
    delete *iter;
  }

  streams_.clear();
}

}  // namespace pdb
