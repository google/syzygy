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
//
// Defines a set of simple serialization primitives.
//
// *** BASIC USAGE
//
// Serialization of a simple object works as follows:
//
//   Object object;
//   FILE* file = OpenFile("foo.dat", "wb");
//   FileOutStream out_stream(file);
//   NativeBinaryOutArchive out_archive(out_stream);
//   out_archive.Save(object)
//
// To deserialize an object:
//
//   Object object;
//   FILE* file = OpenFile("foo.dat", "rb");
//   FileInStream in_stream(file);
//   NativeBinaryInArchive in_archive(in_stream);
//   in_archive.Load(&object)
//
// Serialization of primitive types (bool, char, wchar_t, float, double,
// int8/16/32/64, uint8/16/32/64), C-arrays of serializable types, and STL
// containers (map, set, vector, basic_string, pair) of serializable types is
// supported by default. Support can be added for further types by extending
// the serialization system directly.
//
// There are currently two stream types defined: File*Stream, which uses a
// FILE* under the hood; and Byte*Stream, which uses iterators to containers
// of Bytes. Adding further stream types is trivial. Refer to to the comments/
// declarations of File*Stream and Byte*Stream for details.
//
// There is currently a single archive type defined, NativeBinary, which is a
// non-portable binary format. Additional archive formats may be easily added
// as well. Refer to the comments/declaration of NativeBinaryInArchive and
// NativeBinaryOutArchive for details.
//
// *** ADDING SERIALIZATION SUPPORT DIRECTLY TO A CLASS:
//
// The object itself supports serialization through a public member function:
//
//   class Object {
//     ...
//     template<class OutArchive> bool Save(OutArchive* out_archive) const {
//       ... calls to out_archive.Save ...
//     }
//   };
//
// To support deserialization, a similar 'Load' function is created with the
// signature:
//
//   template<class InArchive> bool Load(InArchive* in_archive);
//
// *** ADDING SERIALIZATION SUPPORT TO A CLASS IN AN EXTERNAL LIBRARY
//
// If you need to add serialization support to a class in an external library
// (where you can't directly add member functions), you can do so using the
// templated core::Save and core::Load functions. Simply provide an override
// for the appropriate type, with signatures of the form:
//
//   template<class OutArchive> bool Save(const ClassName& data,
//                                        OutArchive* out_archive);
//   template<class InArchive> bool Load(ClassName* data,
//                                       InArchive* in_archive);
//
// *** UNDER THE HOOD
//
// We trace the calltree for the serialization of a Foo object foo:
//
// - An object foo of type Foo is saved to an OutArchive by calling
//   out_archive.Save(foo).
//
// - If OutArchive specializes Save(Foo), then the object is serialized
//   directly (this is the case for primitive types). Otherwise, it is forwarded
//   to core::Save(foo, out_archive).
//
// - If there is a specialized version of core::Save(foo, out_archive), it
//   will be called. This is how STL types and C-arrays are serialized.
//   Otherwise, the generic version of the function will delegate to
//   foo.Save(out_archive).
//
// - If Foo::Save is not defined, compilation will fail.

#ifndef SYZYGY_CORE_SERIALIZATION_H_
#define SYZYGY_CORE_SERIALIZATION_H_

#include <iterator>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"

namespace core {

typedef uint8 Byte;
typedef std::vector<Byte> ByteVector;

namespace internal {

// Forward declares of some utilities we need. These are defined in
// serialization_impl.h.
template<typename T> struct IsByteLike;
template<typename IteratorTag> struct IteratorsAreEqualFunctor;

}  // namespace internal

// Serialization passes through these static functions before being routed
// to 'Save' and 'Load' member functions. Overriding this function provides a
// method to implement serialization for classes whose internals we can not
// modify. This is how serialization is implemented for STL containers in
// serialization_impl.h.
template<class Data, class OutArchive> bool Save(
    const Data& data, OutArchive* out_archive);
template<class Data, class InArchive> bool Load(
    Data* data, InArchive* in_archive);

// We define extremely lightweight stream-like objects for use as the I/O
// layer in serialization. This is so that our Serialization system can easily
// stick to the use of FILE objects.
class OutStream {
 public:
  virtual ~OutStream() { }
  virtual bool Write(size_t length, const Byte* bytes) = 0;
};
class InStream {
 public:
  virtual ~InStream() { }
  virtual bool Read(size_t length, Byte* bytes) = 0;
};
typedef scoped_ptr<OutStream> ScopedOutStreamPtr;
typedef scoped_ptr<InStream> ScopedInStreamPtr;

// A simple OutStream wrapper for FILE pointers.
class FileOutStream : public OutStream {
 public:
  explicit FileOutStream(FILE* file);
  virtual ~FileOutStream() { }
  virtual bool Write(size_t length, const Byte* bytes);
 private:
  FILE* file_;
};

// A simple InStream wrapper for FILE pointers.
class FileInStream : public InStream {
 public:
  explicit FileInStream(FILE* file);
  virtual ~FileInStream() { }
  virtual bool Read(size_t length, Byte* bytes);
 private:
  FILE* file_;
};

// A simple OutStream wrapper for containers of bytes. Uses an output iterator
// to push data to some container, or a pair of non-const iterators to write
// data to a preallocated container. The underlying container should store
// 'byte-like' elements (integer of size 1).
template<typename OutputIterator> class ByteOutStream : public OutStream {
 public:
  // We can't use a compile time assert to validate the value_type of an
  // output iterator, as it is undefined.

  // This constructor is for adding new elements to an existing container.
  // The iterator should be a bonafide OutputIterator.
  explicit ByteOutStream(OutputIterator iter)
      : iter_(iter), end_(iter), have_end_(false) {
  }

  virtual ~ByteOutStream() { }

  // This constructor is for overwriting elements in an existing container.
  // The iterators should be normal non-const iterators.
  ByteOutStream(OutputIterator iter, OutputIterator end)
      : iter_(iter), end_(end), have_end_(true) {
  }

  virtual bool Write(size_t length, const Byte* bytes);

 private:
  typedef typename std::iterator_traits<OutputIterator>::iterator_category
      IteratorTag;
  typedef internal::IteratorsAreEqualFunctor<IteratorTag> IteratorsAreEqual;

  OutputIterator iter_;
  OutputIterator end_;
  bool have_end_;
};

// This is for implicit creation of ByteOutStreams without needing to specify
// template parameters. Use with ScopedOutStreamPtr.
template<typename OutputIterator>
OutStream* CreateByteOutStream(OutputIterator iter) {
  return new ByteOutStream<OutputIterator>(iter);
}
template<typename OutputIterator>
OutStream* CreateByteOutStream(OutputIterator iter, OutputIterator end) {
  return new ByteOutStream<OutputIterator>(iter, end);
}

// A simple InStream wrapper for containers of bytes. Uses a range of input
// iterators to traverse a container. The value type of the iterator must be
// 'byte-like' (integer type of size 1). Use with ScopedInStreamPtr.
template<typename InputIterator> class ByteInStream : public InStream {
 public:
  typedef typename std::iterator_traits<InputIterator>::value_type ValueType;
  COMPILE_ASSERT(internal::IsByteLike<ValueType>::Value,
                 value_type_must_be_byte_like);

  ByteInStream(InputIterator begin, InputIterator end)
      : iter_(begin), end_(end) {
  }

  virtual ~ByteInStream() { }

  virtual bool Read(size_t length, Byte* bytes);

 private:
  InputIterator iter_;
  InputIterator end_;
};

// This is for implicit creation of ByteInStreams without needing to specify
// template parameters.
template<typename InputIterator>
ByteInStream<InputIterator>* CreateByteInStream(InputIterator iter,
                                                InputIterator end) {
  return new ByteInStream<InputIterator>(iter, end);
}

// This class defines a non-portable native binary serialization format.
class NativeBinaryOutArchive {
 public:
  // All classes implementing the OutArchive concept must implement the
  // following 2 functions.

  explicit NativeBinaryOutArchive(OutStream* out_stream)
      : out_stream_(out_stream) {
    DCHECK(out_stream != NULL);
  }

  template<class Data> bool Save(const Data& data) {
    return core::Save(data, this);
  }

  // The following are specializations for primitive data types. Every
  // OutArchive should implement these types directly.
#define NATIVE_BINARY_OUT_ARCHIVE_SAVE(Type) \
  bool Save(const Type& x) { \
    DCHECK(out_stream_ != NULL); \
    return out_stream_->Write(sizeof(Type), \
                              reinterpret_cast<const Byte*>(&x)); \
  }
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(bool);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(char);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(wchar_t);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(float);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(double);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(int8);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(int16);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(int32);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(int64);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(uint8);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(uint16);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(uint32);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(uint64);
  NATIVE_BINARY_OUT_ARCHIVE_SAVE(unsigned long);
#undef NATIVE_BINARY_OUT_ARCHIVE_SAVE

  OutStream* out_stream() { return out_stream_; }

 private:
  OutStream* out_stream_;
};

// For now this is the only archive type, but if there are more OutArchive
// would be the common pure-virtual base class.
typedef NativeBinaryOutArchive OutArchive;

class NativeBinaryInArchive {
 public:
  // All classes implementing the InArchive concept must implement the
  // following 3 functions.

  explicit NativeBinaryInArchive(InStream* in_stream)
      : in_stream_(in_stream) {
    DCHECK(in_stream != NULL);
  }

  template<class Data> bool Load(Data* data) {
    return core::Load(data, this);
  }

  // The following are specializations for primitive data types. Every
  // InArchive should implement these types directly.
#define NATIVE_BINARY_IN_ARCHIVE_LOAD(Type) \
  bool Load(Type* x) { \
    DCHECK(in_stream_ != NULL); \
    return in_stream_->Read(sizeof(Type), reinterpret_cast<Byte*>(x)); \
  }
  NATIVE_BINARY_IN_ARCHIVE_LOAD(bool);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(char);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(wchar_t);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(float);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(double);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(int8);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(int16);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(int32);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(int64);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(uint8);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(uint16);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(uint32);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(uint64);
  NATIVE_BINARY_IN_ARCHIVE_LOAD(unsigned long);
#undef NATIVE_BINARY_IN_ARCHIVE_LOAD

  InStream* in_stream() { return in_stream_; }

 private:
  InStream* in_stream_;
};

// For now this is the only archive type, but if there are more OutArchive
// would be the common pure-virtual base class.
typedef NativeBinaryInArchive InArchive;

}  // namespace core

// Bring in the implementation of the various templated functions.
#include "syzygy/core/serialization_impl.h"

#endif  // SYZYGY_CORE_SERIALIZATION_H_
