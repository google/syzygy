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
// Internal implementation details for msf_reader.h. Not meant to be included
// directly.

#ifndef SYZYGY_MSF_MSF_READER_IMPL_H_
#define SYZYGY_MSF_MSF_READER_IMPL_H_

#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "syzygy/msf/msf_data.h"
#include "syzygy/msf/msf_file_stream.h"

namespace msf {
namespace detail {

namespace {

bool GetFileSize(FILE* file, uint32_t* size) {
  DCHECK(file != NULL);
  DCHECK(size != NULL);

  if (fseek(file, 0, SEEK_END) != 0) {
    LOG(ERROR) << "Failed seeking to end of file.";
    return false;
  }

  long temp = ftell(file);
  if (temp == -1L) {
    LOG(ERROR) << "Failed to read stream position.";
    return false;
  }
  DCHECK_GT(temp, 0);

  (*size) = static_cast<uint32_t>(temp);
  return true;
}

uint32_t GetNumPages(const MsfHeader& header, uint32_t num_bytes) {
  return (num_bytes + header.page_size - 1) / header.page_size;
}

}  // namespace

template <MsfFileType T>
bool MsfReaderImpl<T>::Read(const base::FilePath& msf_path,
                            MsfFileImpl<T>* msf_file) {
  DCHECK(msf_file != NULL);

  msf_file->Clear();

  scoped_refptr<RefCountedFILE> file(
      new RefCountedFILE(base::OpenFile(msf_path, "rb")));
  if (!file->file()) {
    LOG(ERROR) << "Unable to open '" << msf_path.value() << "'.";
    return false;
  }

  // Get the file size.
  uint32_t file_size = 0;
  if (!GetFileSize(file->file(), &file_size)) {
    LOG(ERROR) << "Unable to determine size of '" << msf_path.value() << "'.";
    return false;
  }

  MsfHeader header = {0};

  // Read the header from the first page in the file. The page size we use here
  // is irrelevant as after reading the header we get the actual page size in
  // use by the MSF and from then on use that.
  uint32_t header_page = 0;
  scoped_refptr<MsfFileStreamImpl<T>> header_stream(new MsfFileStreamImpl<T>(
      file.get(), sizeof(header), &header_page, kMsfPageSize));
  if (!header_stream->ReadBytesAt(0, sizeof(header), &header)) {
    LOG(ERROR) << "Failed to read MSF file header.";
    return false;
  }

  // Sanity checks.
  if (header.num_pages * header.page_size != file_size) {
    LOG(ERROR) << "Invalid MSF file size.";
    return false;
  }

  if (memcmp(header.magic_string, kMsfHeaderMagicString,
             sizeof(kMsfHeaderMagicString)) != 0) {
    LOG(ERROR) << "Invalid MSF magic string.";
    return false;
  }

  // Load the directory page list (a sequence of uint32_t page numbers that is
  // itself written across multiple root pages). To do this we need to know how
  // many pages are required to represent the directory, then we load a stream
  // containing that many page pointers from the root pages array.
  int num_dir_pages =
      static_cast<int>(GetNumPages(header, header.directory_size));
  scoped_refptr<MsfFileStreamImpl<T>> dir_page_stream(
      new MsfFileStreamImpl<T>(file.get(), num_dir_pages * sizeof(uint32_t),
                               header.root_pages, header.page_size));
  std::unique_ptr<uint32_t[]> dir_pages(new uint32_t[num_dir_pages]);
  if (dir_pages.get() == NULL) {
    LOG(ERROR) << "Failed to allocate directory pages.";
    return false;
  }
  size_t page_dir_size = num_dir_pages * sizeof(uint32_t);
  if (!dir_page_stream->ReadBytesAt(0, page_dir_size, dir_pages.get())) {
    LOG(ERROR) << "Failed to read directory page stream.";
    return false;
  }

  // Load the actual directory.
  size_t dir_size =
      static_cast<size_t>(header.directory_size / sizeof(uint32_t));
  scoped_refptr<MsfFileStreamImpl<T>> dir_stream(new MsfFileStreamImpl<T>(
      file.get(), header.directory_size, dir_pages.get(), header.page_size));
  std::vector<uint32_t> directory(dir_size);
  if (!dir_stream->ReadBytesAt(0, dir_size * sizeof(uint32_t), &directory[0])) {
    LOG(ERROR) << "Failed to read directory stream.";
    return false;
  }

  // Iterate through the streams and construct MsfStreams.
  const uint32_t& num_streams = directory[0];
  const uint32_t* stream_lengths = &(directory[1]);
  const uint32_t* stream_pages = &(directory[1 + num_streams]);

  uint32_t page_index = 0;
  for (uint32_t stream_index = 0; stream_index < num_streams; ++stream_index) {
    msf_file->AppendStream(
        new MsfFileStreamImpl<T>(file.get(), stream_lengths[stream_index],
                                 stream_pages + page_index, header.page_size));
    page_index += GetNumPages(header, stream_lengths[stream_index]);
  }

  return true;
}

}  // namespace detail
}  // namespace msf

#endif  // SYZYGY_MSF_MSF_READER_IMPL_H_
