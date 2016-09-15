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

#ifndef SYZYGY_MSF_MSF_WRITER_IMPL_H_
#define SYZYGY_MSF_MSF_WRITER_IMPL_H_

#include <cstdio>
#include <cstring>
#include <vector>

#include "base/logging.h"
#include "syzygy/msf/msf_constants.h"
#include "syzygy/msf/msf_data.h"

namespace msf {
namespace detail {

namespace {

const uint32_t kZeroBuffer[kMsfPageSize] = {0};

// A byte-based bitmap for keeping track of free pages in an MSF file.
// TODO(chrisha): Promote this to its own file and unittest it when we make
//     a library for MSF-specific stuff.
class FreePageBitMap {
 public:
  FreePageBitMap() : page_count_(0) {}

  void SetPageCount(uint32_t page_count) {
    page_count_ = page_count;
    data_.resize((page_count + 7) / 8);

    // Double check our invariant.
    DCHECK_LE(page_count, data_.size() * 8);
    DCHECK_LE(page_count / 8, data_.size());
  }

  void SetBit(uint32_t page_index, bool free) {
    DCHECK_LT(page_index, page_count_);

    uint32_t byte = page_index / 8;
    uint32_t bit = page_index % 8;
    uint8_t bitmask = 1 << bit;
    DCHECK_LT(byte, data_.size());

    if (free) {
      data_[byte] |= bitmask;
    } else {
      data_[byte] &= ~bitmask;
    }
  }

  void SetFree(uint32_t page_index) { SetBit(page_index, true); }
  void SetUsed(uint32_t page_index) { SetBit(page_index, false); }

  // TODO(chrisha): Make this an invariant of the class and move the logic
  //     to SetPageCount. This involves both clearing and setting bits in that
  //     case.
  void Finalize() {
    uint32_t bits_left = static_cast<uint32_t>(data_.size()) * 8 - page_count_;
    DCHECK_LE(bits_left, 7u);

    // This leaves the top |bits_left| bits set.
    uint8_t bitmask = ~(0xFF >> bits_left);

    // Mark any bits as free beyond those specifically allocated.
    data_.back() |= bitmask;
  }

  const std::vector<uint8_t>& data() const { return data_; }

 private:
  std::vector<uint8_t> data_;
  uint32_t page_count_;
};

// A light-weight wrapper that allows a previously allocated buffer to be read
// as an MsfStreamImpl.
template <MsfFileType T>
class ReadOnlyMsfStream : public MsfStreamImpl<T> {
 public:
  ReadOnlyMsfStream(const void* data, uint32_t bytes)
      : MsfStreamImpl(bytes), data_(data) {}

  bool ReadBytesAt(size_t pos, size_t count, void* dest) override {
    DCHECK(dest != NULL);

    if (count > length() - pos)
      return false;

    ::memcpy(dest, reinterpret_cast<const uint8_t*>(data_) + pos, count);

    return true;
  }

 private:
  const void* data_;
};

// Appends a page to the provided file, adding the written page ID to the vector
// of @p pages_written, and incrementing the total @P page_count. This will
// occasionally cause more than one single page to be written to the output,
// thus advancing @p page_count by more than one (when reserving pages for the
// free page map). It is expected that @data be kMsfPageSize in length.
// @pre the file is expected to be positioned at @p *page_count * kMsfPageSize
//     when entering this routine
// @post the file will be positioned at @p *page_count * kMsfPageSiz when
//     exiting this routine.
bool AppendPage(const void* data,
                std::vector<uint32_t>* pages_written,
                uint32_t* page_count,
                FILE* file) {
  DCHECK(data != NULL);
  DCHECK(pages_written != NULL);
  DCHECK(page_count != NULL);
  DCHECK(file != NULL);

  uint32_t local_page_count = *page_count;

  // The file is written sequentially, so it will already be pointing to
  // the appropriate spot.
  DCHECK_EQ(local_page_count * kMsfPageSize,
            static_cast<uint32_t>(::ftell(file)));

  // If we're due to allocate pages for the free page map, then do so.
  if (((*page_count) % kMsfPageSize) == 1) {
    if (::fwrite(kZeroBuffer, 1, kMsfPageSize, file) != kMsfPageSize ||
        ::fwrite(kZeroBuffer, 1, kMsfPageSize, file) != kMsfPageSize) {
      LOG(ERROR) << "Failed to allocate free page map pages.";
      return false;
    }
    local_page_count += 2;
  }

  // Write the page itself.
  if (::fwrite(data, 1, kMsfPageSize, file) != kMsfPageSize) {
    LOG(ERROR) << "Failed to write page " << *page_count << ".";
    return false;
  }
  pages_written->push_back(local_page_count);
  ++local_page_count;

  DCHECK_EQ(local_page_count * kMsfPageSize,
            static_cast<uint32_t>(::ftell(file)));

  *page_count = local_page_count;
  return true;
}

bool WriteFreePageBitMap(const FreePageBitMap& free, FILE* file) {
  DCHECK(file != NULL);

  const uint8_t* data = free.data().data();
  size_t bytes_left = free.data().size();
  size_t page_index = 1;
  size_t bytes_to_write = kMsfPageSize;
  while (true) {
    if (::fseek(file,
                static_cast<long>(page_index * kMsfPageSize),
                SEEK_SET) != 0) {
      LOG(ERROR) << "Failed to seek to page " << page_index << ".";
      return false;
    }

    bytes_to_write = kMsfPageSize;
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
    page_index += kMsfPageSize;
  }

  // Was the last write partial? If so, we need to flush out the rest of the
  // free page map with ones (0xFF bytes).
  if (bytes_to_write < kMsfPageSize) {
    // Create a vector of bytes with all the bits set.
    std::vector<uint8_t> ones(kMsfPageSize - bytes_to_write, 0xFF);
    if (::fwrite(ones.data(), 1, ones.size(), file) != ones.size()) {
      LOG(ERROR) << "Failed to pad page " << page_index << " of free page map.";
      return false;
    }
  }

  return true;
}

}  // namespace

template <MsfFileType T>
MsfWriterImpl<T>::MsfWriterImpl() {
}

template <MsfFileType T>
MsfWriterImpl<T>::~MsfWriterImpl() {
}

template <MsfFileType T>
bool MsfWriterImpl<T>::Write(const base::FilePath& msf_path,
                             const MsfFileImpl<T>& msf_file) {
  file_.reset(base::OpenFile(msf_path, "wb"));
  if (!file_.get()) {
    LOG(ERROR) << "Failed to create '" << msf_path.value() << "'.";
    return false;
  }

  // Initialize the directory with stream count and lengths.
  std::vector<uint32_t> directory;
  directory.push_back(static_cast<uint32_t>(msf_file.StreamCount()));
  for (uint32_t i = 0; i < msf_file.StreamCount(); ++i) {
    // Null streams have an implicit zero length.
    MsfStreamImpl<T>* stream = msf_file.GetStream(i).get();
    if (stream == NULL)
      directory.push_back(0);
    else
      directory.push_back(static_cast<uint32_t>(stream->length()));
  }

  // Reserve space for the header page, the two free page map pages, and a
  // fourth empty page. The fourth empty page doesn't appear to be strictly
  // necessary but MSF files produced by MS tools always contain it.
  uint32_t page_count = 4;
  for (uint32_t i = 0; i < page_count; ++i) {
    if (::fwrite(kZeroBuffer, 1, kMsfPageSize, file_.get()) != kMsfPageSize) {
      LOG(ERROR) << "Failed to allocate preamble page.";
      return false;
    }
  }

  // Append all the streams after the preamble and build the directory while
  // we're at it. We keep track of which pages host stream 0 for some free page
  // map bookkeeping later on.
  size_t stream0_start = directory.size();
  size_t stream0_end = 0;
  for (uint32_t i = 0; i < msf_file.StreamCount(); ++i) {
    if (i == 1)
      stream0_end = directory.size();

    // Null streams are treated as empty streams.
    MsfStreamImpl<T>* stream = msf_file.GetStream(i).get();
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
  std::vector<uint32_t> directory_pages;
  scoped_refptr<MsfStreamImpl<T>> directory_stream(new ReadOnlyMsfStream<T>(
      directory.data(),
      static_cast<uint32_t>(sizeof(directory[0]) * directory.size())));
  if (!AppendStream(directory_stream.get(), &directory_pages, &page_count)) {
    LOG(ERROR) << "Failed to write directory.";
    return false;
  }

  // Write the root directory, and keep track of the pages it is written to.
  // These will in turn go into the header root directory pointers.
  std::vector<uint32_t> root_directory_pages;
  scoped_refptr<MsfStreamImpl<T>> root_directory_stream(
      new ReadOnlyMsfStream<T>(
          directory_pages.data(),
          sizeof(directory_pages[0]) *
              static_cast<uint32_t>(directory_pages.size())));
  if (!AppendStream(root_directory_stream.get(), &root_directory_pages,
                    &page_count)) {
    LOG(ERROR) << "Failed to write root directory.";
    return false;
  }

  // Write the header.
  if (!WriteHeader(root_directory_pages,
                   static_cast<uint32_t>(
                       sizeof(directory[0]) * directory.size()),
                   page_count)) {
    LOG(ERROR) << "Failed to write MSF header.";
    return false;
  }

  // Initialize the free page bit map. The pages corresponding to stream 0 are
  // always marked as free, as well as page 3 which we allocated in the
  // preamble.
  FreePageBitMap free_page;
  free_page.SetPageCount(page_count);
  free_page.SetFree(3);
  for (size_t i = stream0_start; i < stream0_end; ++i)
    free_page.SetFree(directory[i]);
  free_page.Finalize();

  if (!WriteFreePageBitMap(free_page, file_.get())) {
    LOG(ERROR) << "Failed to write free page bitmap.";
    return false;
  }

  // On success we want the file to be closed right away.
  file_.reset();

  return true;
}

template <MsfFileType T>
bool MsfWriterImpl<T>::AppendStream(MsfStreamImpl<T>* stream,
                                    std::vector<uint32_t>* pages_written,
                                    uint32_t* page_count) {
  DCHECK(stream != NULL);
  DCHECK(pages_written != NULL);
  DCHECK(page_count != NULL);

#ifndef NDEBUG
  size_t old_pages_written_count = pages_written->size();
#endif

  // Write the stream page by page.
  uint8_t buffer[kMsfPageSize] = {0};
  size_t bytes_left = stream->length();
  size_t bytes_read = 0;
  while (bytes_left) {
    size_t bytes_to_read = sizeof(buffer);
    if (bytes_to_read > bytes_left) {
      bytes_to_read = bytes_left;

      // If we're only reading a partial buffer then pad the end of it with
      // zeros.
      ::memset(buffer + bytes_to_read, 0, sizeof(buffer) - bytes_to_read);
    }

    // Read the buffer from the stream.
    if (!stream->ReadBytesAt(bytes_read, bytes_to_read, buffer)) {
      size_t offset = stream->length() - bytes_left;
      LOG(ERROR) << "Failed to read " << bytes_to_read << " bytes at offset "
                 << offset << " of MSF stream.";
      return false;
    }
    if (!AppendPage(buffer, pages_written, page_count, file_.get()))
      return false;

    bytes_read += bytes_to_read;
    bytes_left -= bytes_to_read;
  }
  DCHECK_EQ(0u, bytes_left);

#ifndef NDEBUG
  size_t expected_pages_written =
      (stream->length() + kMsfPageSize - 1) / kMsfPageSize;
  DCHECK_EQ(old_pages_written_count + expected_pages_written,
            pages_written->size());
// We can't say anything about |page_count| as AppendPage occasionally snags
// extra pages for the free page map.
#endif

  return true;
}

template <MsfFileType T>
bool MsfWriterImpl<T>::WriteHeader(
    const std::vector<uint32_t>& root_directory_pages,
    uint32_t directory_size,
    uint32_t page_count) {
  VLOG(1) << "Writing MSF Header ...";

  MsfHeader header = {0};

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

  ::memcpy(header.magic_string, kMsfHeaderMagicString,
           sizeof(kMsfHeaderMagicString));
  header.page_size = kMsfPageSize;
  header.free_page_map = 1;
  header.num_pages = page_count;
  header.directory_size = directory_size;
  header.reserved = 0;
  ::memcpy(header.root_pages, root_directory_pages.data(),
           sizeof(root_directory_pages[0]) * root_directory_pages.size());

  if (::fwrite(&header, sizeof(header), 1, file_.get()) != 1) {
    LOG(ERROR) << "Failed to write header.";
    return false;
  }

  return true;
}

}  // namespace detail
}  // namespace msf

#endif  // SYZYGY_MSF_MSF_WRITER_IMPL_H_
