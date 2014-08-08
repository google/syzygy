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

#include "syzygy/core/zstream.h"

#include "syzygy/core/serialization.h"
#include "third_party/zlib/zlib.h"

namespace core {

namespace {

// The size of the intermediate buffers used by the streams. This has no
// bearing on the compression performance, but rather limits how often we have
// to go in and out of zlib. There is no meaningful way to have the buffers
// grow dynamically so we simply use a page of memory.
static const size_t kZStreamBufferSize = 4096;

}  // namespace

void ZOutStream::z_stream_s_close::operator()(z_stream_s* zstream) const {
  if (zstream != NULL) {
    deflateEnd(zstream);
    delete zstream;
  }
}

ZOutStream::ZOutStream(OutStream* out_stream)
    : out_stream_(out_stream), buffer_(kZStreamBufferSize, 0) {
}

ZOutStream::~ZOutStream() { }

bool ZOutStream::Init() {
  return Init(Z_DEFAULT_COMPRESSION);
}

bool ZOutStream::Init(int level) {
  DCHECK(level == Z_DEFAULT_COMPRESSION || (level >= 0 && level <= 9));

  if (zstream_ != NULL)
    return true;

  scoped_ptr<z_stream_s> zstream(new z_stream_s);
  ::memset(zstream.get(), 0, sizeof(*zstream.get()));

  int ret = deflateInit(zstream.get(), level);
  if (ret != Z_OK) {
    LOG(ERROR) << "deflateInit returned " << ret << ": " << zstream_->msg
               << ".";
    return false;
  }

  zstream->next_out = reinterpret_cast<Bytef*>(&buffer_[0]);
  zstream->avail_out = buffer_.size();

  zstream_.reset(zstream.release());

  return true;
}

bool ZOutStream::Write(size_t length, const Byte* bytes) {
  DCHECK(zstream_.get() != NULL);
  DCHECK_EQ(buffer_.size(), kZStreamBufferSize);

  if (length == 0)
    return true;

  DCHECK(bytes != NULL);

  // Continue while we have data to process.
  zstream_->avail_in = length;
  zstream_->next_in = reinterpret_cast<Bytef*>(const_cast<Byte*>(bytes));
  while (zstream_->avail_in > 0) {
    // We don't do any forced flushing so as to have maximum compression.
    int ret = deflate(zstream_.get(), Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_BUF_ERROR) {
      LOG(ERROR) << "zlib deflate returned " << ret << ": " << zstream_->msg
                 << ".";
      return false;
    }

    // Spit out any output that was produced.
    if (!FlushBuffer())
      return false;
  }

  return true;
}

bool ZOutStream::Flush() {
  DCHECK(zstream_.get() != NULL);
  DCHECK_EQ(buffer_.size(), kZStreamBufferSize);

  while (true) {
    int ret = deflate(zstream_.get(), Z_FINISH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
      LOG(ERROR) << "zlib deflate returned " << ret << ": " << zstream_->msg
                 << ".";
    }

    if (!FlushBuffer())
      return false;

    if (ret == Z_STREAM_END)
      break;
  }

  zstream_.reset();

  return true;
}

bool ZOutStream::FlushBuffer() {
  DCHECK(zstream_.get() != NULL);
  DCHECK_EQ(buffer_.size(), kZStreamBufferSize);

  size_t bytes_to_write = buffer_.size() - zstream_->avail_out;
  if (bytes_to_write == 0)
    return true;

  if (!out_stream_->Write(bytes_to_write, &buffer_[0])) {
    LOG(ERROR) << "Unable to write compressed stream.";
    return false;
  }

  // Update the output buffer data.
  zstream_->next_out = reinterpret_cast<Bytef*>(&buffer_[0]);
  zstream_->avail_out = buffer_.size();

  return true;
}

void ZInStream::z_stream_s_close::operator()(z_stream_s* zstream) const {
  if (zstream != NULL) {
    inflateEnd(zstream);
    delete zstream;
  }
}

ZInStream::ZInStream(InStream* in_stream)
    : in_stream_(in_stream), buffer_(kZStreamBufferSize, 0) {
  DCHECK(in_stream != NULL);
}

ZInStream::~ZInStream() { }

bool ZInStream::Init() {
  if (zstream_.get() != NULL)
    return true;

  scoped_ptr<z_stream_s> zstream(new z_stream_s);
  ::memset(zstream.get(), 0, sizeof(*zstream.get()));

  int ret = inflateInit(zstream.get());
  if (ret != Z_OK) {
    LOG(ERROR) << "inflateInit returned " << ret << ": " << zstream_->msg
               << ".";
    return false;
  }

  zstream_.reset(zstream.release());

  return true;
}

bool ZInStream::ReadImpl(size_t length, Byte* bytes, size_t* bytes_read) {
  DCHECK(bytes_read != NULL);

  *bytes_read = 0;
  if (length == 0)
    return true;

  DCHECK(bytes != NULL);

  // If we're not initialized we're at the end of the stream. This is not an
  // error, there's simply no more data to be consumed from this stream.
  if (zstream_.get() == NULL)
    return true;

  DCHECK_EQ(buffer_.size(), kZStreamBufferSize);

  zstream_->next_out = reinterpret_cast<Bytef*>(bytes);
  zstream_->avail_out = length;

  int ret = Z_OK;
  while (true) {
    // Try reading from the zstream right away. It's possible for the input
    // buffer to be exhausted, but for there to still be data to output.
    ret = inflate(zstream_.get(), Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_BUF_ERROR && ret != Z_STREAM_END) {
      LOG(ERROR) << "zlib inflate returned " << ret << ": " << zstream_->msg
                 << ".";
      return false;
    }

    // No more data, or no more room to write more data? Then we're done
    // for now.
    if (ret == Z_STREAM_END || zstream_->avail_out == 0)
      break;

    // If we get here, then there was room to output more data yet that wasn't
    // done. Thus, we must need more input.
    if (zstream_->avail_in != 0) {
      LOG(ERROR) << "zlib won't emit more data, but has input to work with.";
      return false;
    }

    // We expect *some* data to be read.
    size_t bytes_read = 0;
    if (!in_stream_->Read(buffer_.size(), &buffer_[0], &bytes_read)) {
      LOG(ERROR) << "Unable to read data from input stream.";
      return false;
    }
    if (bytes_read == 0) {
      LOG(ERROR) << "zlib expects more data but input stream is exhausted.";
      return false;
    }
    zstream_->next_in = reinterpret_cast<Bytef*>(&buffer_[0]);
    zstream_->avail_in = bytes_read;
  }

  *bytes_read = length - zstream_->avail_out;

  // Is the zstream exhausted? Then we can clean up this stream to indicate
  // end of stream to further calls.
  if (ret == Z_STREAM_END && zstream_->avail_out == 0)
    zstream_.reset();

  return true;
}

}  // namespace core
