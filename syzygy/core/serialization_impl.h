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
// Contains Serialization implementation details. See 'serialization.h'
// for more information. This file is not meant to be included directly,
// but is brought in by serialization.h.

#ifndef SYZYGY_CORE_SERIALIZATION_IMPL_H_
#define SYZYGY_CORE_SERIALIZATION_IMPL_H_

#include <iterator>

// Forward declare base::Time, defined in "base/time/time.h".
namespace base {
class Time;
}  // namespace base

// Forward declare the OMAP struct. This is defined in DbgHelp.h.
struct _OMAP;
typedef struct _OMAP OMAP;

namespace core {

namespace internal {

// This is for testing type equality.
template<typename T1, typename T2> struct TypesAreEqual {
  enum { Value = 0 };
};
template<typename T> struct TypesAreEqual<T, T> {
  enum { Value = 1 };
};

// This tests that a given type is a signed or unsigned 1-byte type.
template<typename T> struct IsByteLike {
  enum {
    Value = (TypesAreEqual<T, int8>::Value || TypesAreEqual<T, uint8>::Value) &&
        (sizeof(T) == 1)
  };
};

// This compares two iterators. It only does so if the iterator type is
// not an output iterator.
template<typename IteratorTag> struct IteratorsAreEqualFunctor {
  template<typename Iterator> bool operator()(Iterator it1, Iterator it2) {
    return it1 == it2;
  }
};
template<> struct IteratorsAreEqualFunctor<std::output_iterator_tag> {
  template<typename Iterator> bool operator()(Iterator it1, Iterator it2) {
    return false;
  }
};

// Serialization for STL containers. This expects the container to implement
// 'size', and iterators.
template<class Container, class OutArchive> bool SaveContainer(
    const Container& container, OutArchive* out_archive) {
  DCHECK(out_archive != NULL);

  if (!out_archive->Save(container.size()))
    return false;

  typename Container::const_iterator it = container.begin();
  for (; it != container.end(); ++it) {
    if (!out_archive->Save(*it))
      return false;
  }

  return true;
}

// We use this type traits struct to get the value_type associated with a
// given container. We require this to get around the pair<const, non-const>
// value_type declaration of std::map.
template<class Container> struct ContainerValueType {
  typedef typename Container::value_type ValueType;
};
template<typename Key, typename Data, typename Compare, typename Alloc>
struct ContainerValueType<std::map<Key, Data, Compare, Alloc> > {
  typedef std::pair<Key, Data> ValueType;
};

// Reserves space in a container for the given number of entries, if possible.
template<typename Container>
struct ReserveContainer {
  void operator()(size_t entries, Container* container) {
    // Do nothing for most containers.
  }
};
// std::vector and std::basic_string both support 'reserve'.
template<typename T>
struct ReserveContainer<std::vector<T>> {
  void operator()(size_t entries, std::vector<T>* vector) {
    DCHECK(vector != NULL);
    vector->reserve(entries);
  }
};
template<typename Char, typename Traits, typename Alloc>
struct ReserveContainer<std::basic_string<Char, Traits, Alloc>> {
  void operator()(size_t entries,
                  std::basic_string<Char, Traits, Alloc>* string) {
    DCHECK(string != NULL);
    string->reserve(entries);
  }
};

// Loads serialized values into a container via an output iterator.
template<typename Container, typename OutputIterator, class InArchive>
bool LoadContainer(Container* container,
                   OutputIterator output_iterator,
                   InArchive* in_archive) {
  DCHECK(container != NULL);
  DCHECK(in_archive != NULL);

  // Get the value type.
  typedef ContainerValueType<Container>::ValueType ValueType;

  typename Container::size_type size = 0;
  if (!in_archive->Load(&size))
    return false;

  // Reserve room for the entries, if the container supports it. This makes
  // this slightly more efficient.
  ReserveContainer<Container>()(size, container);

  typename Container::size_type i = 0;
  for (; i < size; ++i) {
    ValueType value;
    if (!in_archive->Load(&value))
      return false;
    *output_iterator = value;
    ++output_iterator;
  }

  DCHECK_EQ(size, container->size());

  return true;
}

}  // namespace internal

template<typename OutputIterator> bool ByteOutStream<OutputIterator>::Write(
    size_t length, const Byte* bytes) {
  for (size_t i = 0; i < length; ++i, ++bytes) {
    if (have_end_ && IteratorsAreEqual()(iter_, end_))
      return false;
    // The underlying output type has to be able to cope with
    // assignment from a Byte!
    *iter_ = *bytes;
    ++iter_;
  }
  return true;
}

template<typename InputIterator> bool ByteInStream<InputIterator>::ReadImpl(
    size_t length, Byte* bytes, size_t* bytes_read) {
  DCHECK(bytes != NULL);
  DCHECK(bytes_read != NULL);

  Byte* bytes_start = bytes;
  for (size_t i = 0; i < length; ++i, ++bytes) {
    if (iter_ == end_)
      break;
    *bytes = static_cast<Byte>(*iter_);
    ++iter_;
  }

  *bytes_read = static_cast<size_t>(bytes - bytes_start);
  return true;
}

// Default implementations of core::Save and core::Load.

// This delegates to Data::Save.
template<class Data, class OutArchive> bool Save(
    const Data& data, OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return data.Save(out_archive);
}

// This delegates to Data::Load.
template<class Data, class InArchive> bool Load(
    Data* data, InArchive* in_archive) {
  DCHECK(data != NULL);
  DCHECK(in_archive != NULL);
  return data->Load(in_archive);
}

// Implementation of STL Save specializations.

template<typename Char, typename Traits, typename Alloc, class OutArchive>
bool Save(const std::basic_string<Char, Traits, Alloc>& string,
          OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return internal::SaveContainer(string, out_archive);
}

template<typename Key, typename Data, typename Compare, typename Alloc,
         class OutArchive>
bool Save(const std::map<Key, Data, Compare, Alloc>& map,
          OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return internal::SaveContainer(map, out_archive);
}

template<typename Type1, typename Type2, class OutArchive>
bool Save(const std::pair<Type1, Type2>& pair,
          OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return out_archive->Save(pair.first) && out_archive->Save(pair.second);
}

template<typename Key, typename Compare, typename Alloc, class OutArchive>
bool Save(const std::set<Key, Compare, Alloc>& set,
          OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return internal::SaveContainer(set, out_archive);
}

template<typename Type, typename Alloc, class OutArchive>
bool Save(const std::vector<Type, Alloc>& vector,
          OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  return internal::SaveContainer(vector, out_archive);
}

// Implementation of STL Load specializations.

template<typename Char, typename Traits, typename Alloc, class InArchive>
bool Load(std::basic_string<Char, Traits, Alloc>* string,
          InArchive* in_archive) {
  DCHECK(string != NULL);
  DCHECK(in_archive != NULL);
  string->clear();
  return internal::LoadContainer(string,
                                 std::back_inserter(*string),
                                 in_archive);
}

template<typename Key, typename Data, typename Compare, typename Alloc,
         class InArchive>
bool Load(std::map<Key, Data, Compare, Alloc>* map,
          InArchive* in_archive) {
  DCHECK(map != NULL);
  DCHECK(in_archive != NULL);
  map->clear();
  return internal::LoadContainer(map,
                                 std::inserter(*map, map->begin()),
                                 in_archive);
}

template<typename Type1, typename Type2, class InArchive>
bool Load(std::pair<Type1, Type2>* pair,
          InArchive* in_archive) {
  DCHECK(pair != NULL);
  DCHECK(in_archive != NULL);
  return in_archive->Load(&(pair->first)) && in_archive->Load(&(pair->second));
}

template<typename Key, typename Compare, typename Alloc, class InArchive>
bool Load(std::set<Key, Compare, Alloc>* set,
          InArchive* in_archive) {
  DCHECK(set != NULL);
  DCHECK(in_archive != NULL);
  set->clear();
  return internal::LoadContainer(set,
                                 std::inserter(*set, set->begin()),
                                 in_archive);
}

template<typename Type, typename Alloc, class InArchive>
bool Load(std::vector<Type, Alloc>* vector,
          InArchive* in_archive) {
  DCHECK(vector != NULL);
  DCHECK(in_archive != NULL);
  return internal::LoadContainer(vector,
                                 std::back_inserter(*vector),
                                 in_archive);
}

// Implementation of serialization for C-style arrays.

template<typename Type, size_t Length, class OutArchive>
bool Save(const Type (&data)[Length], OutArchive* out_archive) {
  DCHECK(out_archive != NULL);
  for (size_t i = 0; i < Length; ++i) {
    if (!out_archive->Save(data[i]))
      return false;
  }
  return true;
}

template<typename Type, size_t Length, class InArchive>
bool Load(Type (*data)[Length], InArchive* in_archive) {
  DCHECK(data != NULL);
  DCHECK(in_archive != NULL);
  for (size_t i = 0; i < Length; ++i) {
    if (!in_archive->Load(&((*data)[i])))
      return false;
  }
  return true;
}

// Declaration of serialization for base::Time.
bool Save(const base::Time& time, OutArchive* out_archive);
bool Load(base::Time* time, InArchive* in_archive);

// Declaration of OMAP struct serialization.
bool Save(const OMAP& omap, OutArchive* out_archive);
bool Load(OMAP* omap, InArchive* in_archive);

}  // namespace core

#endif  // SYZYGY_CORE_SERIALIZATION_IMPL_H_
