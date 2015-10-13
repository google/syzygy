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
// Declares the different type of MSF files that we can encounter and forward
// declare some specific types.

#ifndef SYZYGY_MSF_MSF_DECL_H_
#define SYZYGY_MSF_MSF_DECL_H_

namespace msf {

// Different MSF files type that we can encounter.
enum MsfFileType {
  // For the code that should be able to manipulate any kind of MSF file.
  kGenericMsfFileType,

  kPdbMsfFileType,
};

namespace detail {

// Forward declaration of some types that are used in other projects.
template <MsfFileType T>
class MsfFileImpl;
template <MsfFileType T>
class MsfStreamImpl;
template <MsfFileType T>
class WritableMsfStreamImpl;
template <MsfFileType T>
class WritableMsfByteStreamImpl;

}  // namespace detail

}  // namespace msf

#endif  // SYZYGY_MSF_MSF_DECL_H_
