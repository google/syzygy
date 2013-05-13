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

#include "syzygy/pdb/pdb_byte_stream.h"

#include <algorithm>
#include "base/logging.h"

namespace pdb {

// The writable half of an in-memory PDB stream. This is not in an anonymous
// namespace as it is forward declared in the header and is a friend of
// PdbByteStream, allowing access to the underlying storage vector. Once we
// hoist storage to another interface, this implementation can be entirely
// hidden.
class WritablePdbByteStream : public WritablePdbStream {
 public:
  // Constructor.
  // @param pdb_byte_stream a pointer to the PDB byte stream whose data we
  //     wrap.
  explicit WritablePdbByteStream(PdbByteStream* pdb_byte_stream);

 protected:
  // This is protected to enforce use of reference counted pointers.
  virtual ~WritablePdbByteStream();

  // common::BufferWriter implementation.
  virtual uint8* GrowBuffer(size_t size) OVERRIDE;

  // A reference counted pointer to the PdbByteStream we are wrapping.
  scoped_refptr<PdbByteStream> pdb_byte_stream_;
};

PdbByteStream::PdbByteStream() : PdbStream(0), writable_pdb_stream_(NULL) {
}

PdbByteStream::~PdbByteStream() {
}

bool PdbByteStream::Init(const uint8* data, size_t length) {
  set_length(length);
  data_.resize(length);
  memcpy(this->data(), data, length);
  return true;
}

bool PdbByteStream::Init(PdbStream* stream) {
  DCHECK(stream != NULL);

  // Init data members.
  set_length(stream->length());
  data_.resize(length());

  if (data_.empty())
    return true;

  // Read the file stream.
  if (!stream->Seek(0)) {
    LOG(ERROR) << "Failed to seek in pdb stream.";
    return false;
  }
  if (!stream->Read(data(), length())) {
    LOG(ERROR) << "Failed to read pdb stream.";
    return false;
  }

  return true;
}

bool PdbByteStream::ReadBytes(void* dest, size_t count, size_t* bytes_read) {
  DCHECK(dest != NULL);
  DCHECK(bytes_read != NULL);

  // Return 0 once we've reached the end of the stream.
  if (pos() == length()) {
    *bytes_read = 0;
    return true;
  }

  // Don't read beyond the end of the known stream length.
  count = std::min(count, length() - pos());

  // Read the stream.
  memcpy(dest, data() + pos(), count);
  Seek(pos() + count);
  *bytes_read = count;

  return true;
}

scoped_refptr<WritablePdbStream> PdbByteStream::GetWritablePdbStream() {
  // This is very not thread-safe! If we want this to be thread-safe, we'll
  // need to be using thread-safe reference counting, and a little smarts here
  // to ensure we're not mid-destructor on some other thread.
  if (writable_pdb_stream_ == NULL)
    writable_pdb_stream_ = new WritablePdbByteStream(this);
  return scoped_refptr<WritablePdbStream>(writable_pdb_stream_);
}

WritablePdbByteStream::WritablePdbByteStream(PdbByteStream* pdb_byte_stream) {
  DCHECK(pdb_byte_stream != NULL);
  pdb_byte_stream_ = pdb_byte_stream;

  // If the stream contains data, initialize the BufferWriter.
  if (pdb_byte_stream_->length() > 0) {
    SetBuffer(pdb_byte_stream_->data(), pdb_byte_stream_->length());
  }
}

WritablePdbByteStream::~WritablePdbByteStream() {
  // Clear our parent's pointer to us.
  pdb_byte_stream_->writable_pdb_stream_ = NULL;
}

uint8* WritablePdbByteStream::GrowBuffer(size_t size) {
  DCHECK_GT(size, pdb_byte_stream_->data_.size());
  // Resize the vector underlying the PdbByteStream, and notify the parent
  // PdbStream object of the new length.
  pdb_byte_stream_->data_.resize(size);
  pdb_byte_stream_->set_length(size);
  return pdb_byte_stream_->data();
}

}  // namespace pdb
