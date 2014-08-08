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

#include "syzygy/pdb/pdb_writer.h"

#include "base/logging.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_data.h"

namespace pdb {

namespace {

const uint32 kZeroBuffer[kPdbPageSize] = { 0 };

// A byte-based bitmap for keeping track of free pages in an MSF/PDB file.
// TODO(chrisha): Promote this to its own file and unittest it when we make
//     a library for MSF-specific stuff.
class FreePageBitMap {
 public:
  FreePageBitMap() : page_count_(0) {
  }

  void SetPageCount(uint32 page_count) {
    page_count_ = page_count;
    data_.resize((page_count + 7) / 8);

    // Double check our invariant.
    DCHECK_LE(page_count, data_.size() * 8);
    DCHECK_LE(page_count / 8, data_.size());
  }

  void SetBit(uint32 page_index, bool free) {
    DCHECK_LT(page_index, page_count_);

    uint32 byte = page_index / 8;
    uint32 bit = page_index % 8;
    uint8 bitmask = 1 << bit;
    DCHECK_LT(byte, data_.size());

    if (free) {
      data_[byte] |= bitmask;
    } else {
      data_[byte] &= ~bitmask;
    }
  }

  void SetFree(uint32 page_index) { SetBit(page_index, true); }
  void SetUsed(uint32 page_index) { SetBit(page_index, false); }

  // TODO(chrisha): Make this an invariant of the class and move the logic
  //     to SetPageCount. This involves both clearing and setting bits in that
  //     case.
  void Finalize() {
    uint32 bits_left = data_.size() * 8 - page_count_;
    DCHECK_LE(bits_left, 7u);

    // This leaves the top |bits_left| bits set.
    uint8 bitmask = ~(0xFF >> bits_left);

    // Mark any bits as free beyond those specifically allocated.
    data_.back() |= bitmask;
  }

  const std::vector<uint8>& data() const { return data_; }

 private:
  std::vector<uint8> data_;
  uint32 page_count_;
};

// A light-weight wrapper that allows a previously allocated buffer to be read
// as a PdbStream.
class ReadOnlyPdbStream : public PdbStream {
 public:
  ReadOnlyPdbStream(const void* data, size_t bytes)
      : PdbStream(bytes), data_(data) {
  }

  virtual bool ReadBytes(
      void* dest, size_t count, size_t* bytes_read) OVERRIDE {
    DCHECK(dest != NULL);
    DCHECK(bytes_read != NULL);

    bool result = true;
    size_t bytes_to_read = count;
    size_t bytes_left = length() - pos();
    if (bytes_left < bytes_to_read) {
      bytes_to_read = bytes_left;
      result = false;
    }

    ::memcpy(dest, reinterpret_cast<const uint8*>(data_) + pos(),
             bytes_to_read);
    Seek(pos() + bytes_to_read);

    *bytes_read = bytes_to_read;
    return result;
  }

 private:
  const void* data_;
};

// Appends a page to the provided file, adding the written page ID to the vector
// of @p pages_written, and incrementing the total @P page_count. This will
// occasionally cause more than one single page to be written to the output,
// thus advancing @p page_count by more than one (when reserving pages for the
// free page map). It is expected that @data be kPdbPageSize in length.
// @pre the file is expected to be positioned at @p *page_count * kPdbPageSize
//     when entering this routine
// @post the file will be positioned at @p *page_count * kPdbPageSiz when
//     exiting this routine.
bool AppendPage(const void* data,
                std::vector<uint32>* pages_written,
                uint32* page_count,
                FILE* file) {
  DCHECK(data != NULL);
  DCHECK(pages_written != NULL);
  DCHECK(page_count != NULL);
  DCHECK(file != NULL);

  uint32 local_page_count = *page_count;

  // The file is written sequentially, so it will already be pointing to
  // the appropriate spot.
  DCHECK_EQ(local_page_count * kPdbPageSize,
            static_cast<uint32>(::ftell(file)));

  // If we're due to allocate pages for the free page map, then do so.
  if (((*page_count) % kPdbPageSize) == 1) {
    if (::fwrite(kZeroBuffer, 1, kPdbPageSize, file) != kPdbPageSize ||
        ::fwrite(kZeroBuffer, 1, kPdbPageSize, file) != kPdbPageSize) {
      LOG(ERROR) << "Failed to allocate free page map pages.";
      return false;
    }
    local_page_count += 2;
  }

  // Write the page itself.
  if (::fwrite(data, 1, kPdbPageSize, file) != kPdbPageSize) {
    LOG(ERROR) << "Failed to write page " << *page_count << ".";
    return false;
  }
  pages_written->push_back(local_page_count);
  ++local_page_count;

  DCHECK_EQ(local_page_count * kPdbPageSize,
            static_cast<uint32>(::ftell(file)));

  *page_count = local_page_count;
  return true;
}

bool WriteFreePageBitMap(const FreePageBitMap& free, FILE* file) {
  DCHECK(file != NULL);

  const uint8* data = free.data().data();
  size_t bytes_left = free.data().size();
  size_t page_index = 1;
  size_t bytes_to_write = kPdbPageSize;
  while (true) {
    if (::fseek(file, page_index * kPdbPageSize, SEEK_SET) != 0) {
      LOG(ERROR) << "Failed to seek to page " << page_index << ".";
      return false;
    }

    bytes_to_write = kPdbPageSize;
    if (bytes_left < bytes_to_write)
      bytes_to_write = bytes_left;

    if (::fwrite(data, 1, bytes_to_write, file) != bytes_to_write) {
      LOG(ERROR) << "Failed to write page " << page_index
                 << " of free page map.";
      return false;
    }

    bytes_left -= bytes_to_write;
    if (bytes_left == 0)
      break;

    data += bytes_to_write;
    page_index += kPdbPageSize;
  }

  // Was the last write partial? If so, we need to flush out the rest of the
  // free page map with ones (0xFF bytes).
  if (bytes_to_write < kPdbPageSize) {
    // Create a vector of bytes with all the bits set.
    std::vector<uint8> ones(kPdbPageSize - bytes_to_write, 0xFF);
    if (::fwrite(ones.data(), 1, ones.size(), file) != ones.size()) {
      LOG(ERROR) << "Failed to pad page " << page_index
                 << " of free page map.";
      return false;
    }
  }

  return true;
}

}  // namespace

PdbWriter::PdbWriter() {
}

PdbWriter::~PdbWriter() {
}

bool PdbWriter::Write(const base::FilePath& pdb_path, const PdbFile& pdb_file) {
  file_.reset(base::OpenFile(pdb_path, "wb"));
  if (!file_.get()) {
    LOG(ERROR) << "Failed to create '" << pdb_path.value() << "'.";
    return false;
  }

  // Initialize the directory with stream count and lengths.
  std::vector<uint32> directory;
  directory.push_back(pdb_file.StreamCount());
  for (size_t i = 0; i < pdb_file.StreamCount(); ++i) {
    // Null streams have an implicit zero length.
    PdbStream* stream = pdb_file.GetStream(i);
    if (stream == NULL)
      directory.push_back(0);
    else
      directory.push_back(stream->length());
  }

  // Reserve space for the header page, the two free page map pages, and a
  // fourth empty page. The fourth empty page doesn't appear to be strictly
  // necessary but MSF/PDB files produced by MS tools always contain it.
  uint32 page_count = 4;
  for (uint32 i = 0; i < page_count; ++i) {
    if (::fwrite(kZeroBuffer, 1, kPdbPageSize, file_.get()) != kPdbPageSize) {
      LOG(ERROR) << "Failed to allocate preamble page.";
      return false;
    }
  }

  // Append all the streams after the preamble and build the directory while
  // we're at it. We keep track of which pages host stream 0 for some free page
  // map bookkeeping later on.
  size_t stream0_start = directory.size();
  size_t stream0_end = 0;
  for (size_t i = 0; i < pdb_file.StreamCount(); ++i) {
    if (i == 1)
      stream0_end = directory.size();

    // Null streams are treated as empty streams.
    PdbStream* stream = pdb_file.GetStream(i);
    if (stream == NULL || stream->length() == 0)
      continue;

    // Write the stream, updating the directory and page index. This routine
    // takes care of making room for the free page map pages.
    if (!AppendStream(stream, &directory, &page_count)) {
      LOG(ERROR) << "Failed to write stream " << i << ".";
      return false;
    }
  }
  DCHECK_LE(stream0_start, stream0_end);

  // Write the directory, and keep track of the pages it is written to.
  std::vector<uint32> directory_pages;
  scoped_refptr<PdbStream> directory_stream(new ReadOnlyPdbStream(
      directory.data(), sizeof(directory[0]) * directory.size()));
  if (!AppendStream(directory_stream.get(), &directory_pages, &page_count)) {
    LOG(ERROR) << "Failed to write directory.";
    return false;
  }

  // Write the root directory, and keep track of the pages it is written to.
  // These will in turn go into the header root directory pointers.
  std::vector<uint32> root_directory_pages;
  scoped_refptr<PdbStream> root_directory_stream(new ReadOnlyPdbStream(
      directory_pages.data(),
      sizeof(directory_pages[0]) * directory_pages.size()));
  if (!AppendStream(root_directory_stream.get(), &root_directory_pages,
                    &page_count)) {
    LOG(ERROR) << "Failed to write root directory.";
    return false;
  }

  // Write the header.
  if (!WriteHeader(root_directory_pages,
                   sizeof(directory[0]) * directory.size(),
                   page_count)) {
    LOG(ERROR) << "Failed to write PDB header.";
    return false;
  }

  // Initialize the free page bit map. The pages corresponding to stream 0 are
  // always marked as free, as well as page 3 which we allocated in the
  // preamble.
  FreePageBitMap free;
  free.SetPageCount(page_count);
  free.SetFree(3);
  for (size_t i = stream0_start; i < stream0_end; ++i)
    free.SetFree(directory[i]);
  free.Finalize();

  if (!WriteFreePageBitMap(free, file_.get())) {
    LOG(ERROR) << "Failed to write free page bitmap.";
    return false;
  }

  // On success we want the file to be closed right away.
  file_.reset();

  return true;
}

bool PdbWriter::AppendStream(PdbStream* stream,
                             std::vector<uint32>* pages_written,
                             uint32* page_count) {
  DCHECK(stream != NULL);
  DCHECK(pages_written != NULL);
  DCHECK(page_count != NULL);

#ifndef NDEBUG
  size_t old_pages_written_count = pages_written->size();
  size_t old_page_count = *page_count;
#endif

  // Write the stream page by page.
  stream->Seek(0);
  uint8 buffer[kPdbPageSize] = { 0 };
  size_t bytes_left = stream->length();
  while (bytes_left) {
    size_t bytes_to_read = sizeof(buffer);
    if (bytes_to_read > bytes_left) {
      bytes_to_read = bytes_left;

      // If we're only reading a partial buffer then pad the end of it with
      // zeros.
      ::memset(buffer + bytes_to_read, 0, sizeof(buffer) - bytes_to_read);
    }

    // Read the buffer from the stream.
    size_t bytes_read = 0;
    if (!stream->ReadBytes(buffer, bytes_to_read, &bytes_read) ||
        bytes_read != bytes_to_read) {
      size_t offset = stream->length() - bytes_left;
      LOG(ERROR) << "Failed to read " << bytes_to_read << " bytes at offset "
                 << offset << " of PDB stream.";
      return false;
    }

    if (!AppendPage(buffer, pages_written, page_count, file_.get()))
      return false;

    bytes_left -= bytes_read;
  }
  DCHECK_EQ(0u, bytes_left);

#ifndef NDEBUG
  size_t expected_pages_written = (stream->length() + kPdbPageSize - 1) /
      kPdbPageSize;
  DCHECK_EQ(old_pages_written_count + expected_pages_written,
            pages_written->size());
  // We can't say anything about |page_count| as AppendPage occasionally snags
  // extra pages for the free page map.
#endif

  return true;
}

bool PdbWriter::WriteHeader(const std::vector<uint32>& root_directory_pages,
                            size_t directory_size,
                            uint32 page_count) {
  VLOG(1) << "Writing MSF Header ...";

  PdbHeader header = { 0 };

  // Make sure the root directory pointers won't overflow.
  if (root_directory_pages.size() > arraysize(header.root_pages)) {
    LOG(ERROR) << "Too many root directory pages for header ("
               << root_directory_pages.size() << " > "
               << arraysize(header.root_pages) << ").";
    return false;
  }

  // Seek to the beginning of the file so we can stamp in the header.
  if (::fseek(file_.get(), 0, SEEK_SET) != 0) {
    LOG(ERROR) << "Seek failed while writing header.";
    return false;
  }

  ::memcpy(header.magic_string, kPdbHeaderMagicString,
           sizeof(kPdbHeaderMagicString));
  header.page_size = kPdbPageSize;
  header.free_page_map = 1;
  header.num_pages = page_count;
  header.directory_size = directory_size;
  header.reserved = 0;
  ::memcpy(header.root_pages,
           root_directory_pages.data(),
           sizeof(root_directory_pages[0]) * root_directory_pages.size());

  if (::fwrite(&header, sizeof(header), 1, file_.get()) != 1) {
    LOG(ERROR) << "Failed to write header.";
    return false;
  }

  return true;
}

}  // namespace pdb
