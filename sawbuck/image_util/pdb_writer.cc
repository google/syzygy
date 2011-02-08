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

#include "sawbuck/image_util/pdb_writer.h"

#include "base/logging.h"
#include "sawbuck/image_util/pdb_constants.h"

const uint32 kZeroBuffer[kPdbPageSize] = { 0 };

PdbWriter::PdbWriter() {
}

PdbWriter::~PdbWriter() {
}

bool PdbWriter::Write(const FilePath& pdb_path,
                      const std::vector<PdbStream*>& streams) {
  file_.reset(file_util::OpenFile(pdb_path, "wb"));
  if (!file_.get()) {
    LOG(ERROR) << "Failed to create " << pdb_path.value();
    return false;
  }

  uint32 total_bytes = 0;

  // Reserve space for the header and free page map.
  // TODO(rogerm): The free page map is a kludge. This should be sized to
  // correspond to the file instead of just one page. It should be relocated
  // to the end and sized properly.
  if (fseek(file_.get(), kPdbPageSize * 3, SEEK_SET) != 0) {
    LOG(ERROR) << "Failed to reserve header and free page map";
    return false;
  }
  total_bytes += kPdbPageSize * 3;

  // Append all the streams after the header.
  StreamInfoList stream_info_list;
  for (std::vector<PdbStream*>::const_iterator iter = streams.begin();
      iter != streams.end(); iter++) {
    // Save the offset and length for later.
    StreamInfo info = { total_bytes, (*iter)->length() };
    stream_info_list.push_back(info);

    uint32 bytes_written = 0;
    if (!AppendStream(*iter, &bytes_written))
      return false;

    total_bytes += bytes_written;
    DCHECK_EQ(0U, total_bytes % kPdbPageSize);
  }

  // Map out the directory: i.e., pages on which the streams have been written.
  uint32 dir_size = 0;
  uint32 dir_page = total_bytes / kPdbPageSize;
  uint32 bytes_written = 0;
  if (!WriteDirectory(stream_info_list, &dir_size, &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Map out the directory roots: i.e., pages on which the directory has been
  // written.
  uint32 dir_root_size = 0;
  uint32 dir_root_page = (total_bytes / kPdbPageSize);
  if (!WriteDirectoryPages(dir_size, dir_page, &dir_root_size, &bytes_written))
    return false;
  total_bytes += bytes_written;

  // Fill in the MSF header.
  if (!WriteHeader(total_bytes, dir_size, dir_root_size, dir_root_page))
    return false;

  return true;
}

// Write an unsigned 32 bit value to the output file.
bool PdbWriter::WriteUint32(const char* func,
                            const char* desc,
                            uint32 value) {
  DCHECK(func != NULL);
  DCHECK(desc != NULL);

  if (fwrite(&value, sizeof(value), 1, file_.get()) != 1) {
    LOG(ERROR) << func << ": Error writing " << desc;
    return false;
  }

  return true;
}

bool PdbWriter::PadToPageBoundary(const char* func,
                                  uint32 offset,
                                  uint32* padding) {
  DCHECK(padding != NULL);

  *padding = (kPdbPageSize - (offset % kPdbPageSize)) % kPdbPageSize;
  if (fwrite(kZeroBuffer, 1, *padding, file_.get()) != *padding) {
    LOG(ERROR) << func << ": Error padding page";
    return false;
  }

  return true;
}

bool PdbWriter::AppendStream(PdbStream* stream, uint32* bytes_written) {
  DCHECK(bytes_written != NULL);

  // Append the contents of source to output file.
  uint8 buffer[1 << 16];
  while (true) {
    uint32 bytes_read = stream->Read(buffer, sizeof(buffer));
    if (bytes_read == -1) {
      LOG(ERROR) << "Error reading from pdb stream";
      return false;
    } else if (bytes_read == 0) {
      break;
    }

    if (fwrite(buffer, 1, bytes_read, file_.get()) != bytes_read) {
      LOG(ERROR) << "Error appending pdb stream to file";
      return false;
    }
  }

  // Pad to the end of the current page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary("AppendStream", stream->length(), &padding))
    return false;

  *bytes_written = stream->length() + padding;
  DCHECK_EQ(0U, (*bytes_written) % kPdbPageSize);

  return true;
}

bool PdbWriter::WriteDirectory(const StreamInfoList& stream_info_list,
                               uint32* dir_size,
                               uint32* bytes_written) {
  static const char* func = "WriteDirectory";

  VLOG(1) << "Writing directory ...";
  DCHECK(dir_size != NULL);
  DCHECK(bytes_written != NULL);


  // The directory format is:
  //    num_streams   (32-bit)
  //    + stream_length (32-bit) for each stream in num_streams
  //    + page_offset   (32-bit) for each page in each stream in num_streams

  uint32 byte_count = 0;

  // Write the number of streams.
  if (!WriteUint32(func, "stream count", stream_info_list.size()))
    return false;
  byte_count += sizeof(uint32);

  // Write the size of each stream.
  for (StreamInfoList::const_iterator iter = stream_info_list.begin();
       iter != stream_info_list.end(); ++iter) {
    if (!WriteUint32(func, "stream size", iter->size))
      return false;
    byte_count += sizeof(uint32);
  }

  // Write the page numbers for each page in each stream.
  for (StreamInfoList::const_iterator iter = stream_info_list.begin();
       iter != stream_info_list.end(); ++iter) {
    DCHECK_EQ(0U, iter->offset % kPdbPageSize);
    for (uint32 size = 0, page_number = iter->offset / kPdbPageSize;
         size < iter->size;
         size += kPdbPageSize, ++page_number) {
      if (!WriteUint32(func, "page offset", page_number))
        return false;
      byte_count += sizeof(uint32);
    }
  }

  // Pad the directory to the next page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary(func, byte_count, &padding))
    return false;

  // Return the output values
  (*dir_size) = byte_count;
  (*bytes_written) = byte_count + padding;

  DCHECK_EQ(0U, (*bytes_written) % kPdbPageSize);
  return true;
}

bool PdbWriter::WriteDirectoryPages(uint32 dir_size,
                                    uint32 dir_page,
                                    uint32* dir_pages_size,
                                    uint32* bytes_written) {
  static const char* func = "WriteDirectoryPages";

  VLOG(1) << "Writing directory roots...";
  DCHECK(dir_pages_size != NULL);
  DCHECK(bytes_written != NULL);

  // Write all page offsets that are used in the directory.
  uint32 byte_count = 0;
  for (uint32 page_offset = 0; page_offset < dir_size;
       page_offset += kPdbPageSize, ++dir_page) {
    if (!WriteUint32(func, "page offset", dir_page))
      return false;
    byte_count += sizeof(uint32);
  }

  // Pad to a page boundary.
  uint32 padding = 0;
  if (!PadToPageBoundary(func, byte_count, &padding))
    return false;

  (*dir_pages_size) = byte_count;
  (*bytes_written) = byte_count + padding;

  DCHECK_EQ(0U, (*bytes_written) % kPdbPageSize);
  return true;
}

bool PdbWriter::WriteHeader(uint32 file_size,
                            uint32 dir_size,
                            uint32 dir_root_size,
                            uint32 dir_root_page) {
  VLOG(1) << "Writing MSF Header ...";
  DCHECK_EQ(0U, file_size % kPdbPageSize);

  // Make sure the root pages list won't overflow.
  if ((dir_root_size + kPdbPageSize - 1) / kPdbPageSize > kPdbMaxDirPages) {
    LOG(ERROR) << "Too many directory root pages";
    return false;
  }

  if (fseek(file_.get(), 0, SEEK_SET) != 0) {
    LOG(ERROR) << "Seek failed when writing header";
    return false;
  }

  PdbHeader header = { 0 };
  memcpy(header.magic_string, kPdbHeaderMagicString,
         sizeof(kPdbHeaderMagicString));
  header.page_size = kPdbPageSize;
  header.free_page_map = 1;
  header.num_pages = file_size / kPdbPageSize;
  header.directory_size = dir_size;
  header.reserved = 0;

  for (uint32 page_offset = 0; page_offset < dir_root_size;
       page_offset += kPdbPageSize, ++dir_root_page) {
    header.root_pages[page_offset / kPdbPageSize] = dir_root_page;
  }

  if (fwrite(&header, sizeof(header), 1, file_.get()) != 1) {
    LOG(ERROR) << "Failed writing header";
    return false;
  }

  return true;
}
