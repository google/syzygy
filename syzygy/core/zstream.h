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
// Defines simple streams which can zlib compress or decompress data.

#ifndef SYZYGY_CORE_ZSTREAM_H_
#define SYZYGY_CORE_ZSTREAM_H_

#include "base/memory/scoped_ptr.h"
#include "syzygy/core/serialization.h"

// Forward declaration.
struct z_stream_s;

namespace core {

// A zlib compressing out-stream. Acts as a filter, accepting the uncompressed
// input that is pushed to it, and pushing compressed output to the chained
// stream.
class ZOutStream : public OutStream {
 public:
  // @{
  // Constructor.
  // @param out_stream the output stream to receive the compressed data.
  explicit ZOutStream(OutStream* out_stream);
  // @}

  // Destructor.
  virtual ~ZOutStream();

  // These are effectively forwarded from zlib.h.
  static const int kZDefaultCompression = -1;
  static const int kZNoCompression = 0;
  static const int kZBestSpeed = 1;
  static const int kZBestCompression = 9;

  // @{
  // Initializes this compressor. Must be called prior to calling Write.
  // @param level the level of compression. Must be kZDefaultCompression (-1),
  //     or an integer in the range 0..9, inclusive. If not provided defaults to
  //     Z_DEFAULT_COMPRESSION.
  // @returns true on success, false otherwise.
  bool Init();
  bool Init(int level);
  // @}

  // @name OutStream implementation.
  // @{
  // Writes the given buffer of data to the stream. This may or may not produce
  // output in the enclosed out-stream.
  // @param length the number of bytes to write.
  // @param bytes the buffer of data to write.
  // @returns true on success, false otherwise.
  virtual bool Write(size_t length, const Byte* bytes) OVERRIDE;
  // After a call to Flush the compressed stream is closed and further calls to
  // Write will fail. Flush must be called after all writing is finished in
  // order for the output to be well-formed. This does not recursively call
  // flush on the child stream.
  // @returns true on success, false otherwise.
  virtual bool Flush() OVERRIDE;
  // @}

 private:
  // Functor that takes care of cleaning up a zstream object that was
  // initialized with deflateInit.
  struct z_stream_s_close {
    inline void operator()(z_stream_s* zstream) const;
  };

  bool FlushBuffer();

  scoped_ptr<z_stream_s, z_stream_s_close> zstream_;
  OutStream* out_stream_;
  std::vector<uint8> buffer_;
};

// A zlib decompressing in-stream, decompressing the data from the chained
// input stream and returning decompressed data to the caller.
class ZInStream : public InStream {
 public:
  // Constructor.
  // @param in_stream the input stream from which we read compressed data.
  explicit ZInStream(InStream* in_stream);

  // Destructor.
  virtual ~ZInStream();

  // Initializes this decompressor. Must be called prior to calling any read
  // functions.
  bool Init();

 protected:
  // InStream implementation.
  virtual bool ReadImpl(
      size_t length, Byte* bytes, size_t* bytes_read) OVERRIDE;

 private:
  // Functor that takes care of cleaning up a zstream object that was
  // initialized with inflateInit.
  struct z_stream_s_close {
    inline void operator()(z_stream_s* zstream) const;
  };

  scoped_ptr<z_stream_s, z_stream_s_close> zstream_;
  InStream* in_stream_;
  std::vector<uint8> buffer_;
};

}  // namespace core

#endif  // SYZYGY_CORE_ZSTREAM_H_
