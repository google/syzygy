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
// Declares some utilities for dealing with PDB files via the DIA interface.

#ifndef SYZYGY_PE_DIA_UTIL_H_
#define SYZYGY_PE_DIA_UTIL_H_
#include <windows.h>
#include <dia2.h>
#include <vector>
#include "base/file_path.h"

namespace pe {

// The names of various debug streams.
extern const wchar_t kFixupDiaDebugStreamName[];
extern const wchar_t kOmapToDiaDebugStreamName[];
extern const wchar_t kOmapFromDiaDebugStreamName[];

// A trinary value that is returned by search routines.
enum SearchResult {
  // The search completed and the object was found.
  kSearchSucceeded,
  // The search completed, but the object was not found.
  kSearchFailed,
  // The search did not complete due to an error.
  kSearchErrored,
};

// Creates a DiaDataSource object. Logs any errors.
//
// @param created_source pointer that will receive the created object.
// @returns true on success, false otherwise.
bool CreateDiaSource(IDiaDataSource** created_source);

// Creates a dia session for the provided object. Logs any errors.
//
// @param file the file to open.
// @param dia_source the DIA source to use.
// @param dia_session pointer that will receive the created DIA session.
// @return true on success, false otherwise.
bool CreateDiaSession(const FilePath& file,
                      IDiaDataSource* dia_source,
                      IDiaSession** dia_session);

// Find the table with the given IID. Logs any errors.
//
// @param iid the IID of the table to look for.
// @param dia_session the DIA session whose tables are to be queried.
// @param out_table a pointer to the object to receive the table. If the table
//     is not found this will be NULL on return.
// @returns a SearchResult
SearchResult FindDiaTable(const IID& iid,
                          IDiaSession* dia_session,
                          void** out_table);

// Find the table that can be cast to the given Dia interface. Logs any errors.
//
// @tparam T an IDia* intercace.
// @param session the DIA session whose tables are to be queried.
// @param out_table a pointer to the object to receive the table. If the table
//     is not found this will be NULL on return.
// @returns a SearchResult
template <typename T>
SearchResult FindDiaTable(IDiaSession* dia_session, T** out_table);

// Finds teh debug stream with the given name. Logs any errors.
//
// @param name the name of the stream to find.
// @param dia_session the DIA session to search.
// @param dia_debug_stream the pointer that will receive the debug stream, if
//     found.
// @returns a SearchResult.
SearchResult FindDiaDebugStream(const wchar_t* name,
                                IDiaSession* dia_session,
                                IDiaEnumDebugStreamData** dia_debug_stream);

// This reads a given debug stream into the provided vector. The type T
// must be the same size as the debug stream record size. Logs any errors.
//
// @tparam T the type of object to read from the debug stream.
// @param stream the debug stream from which to read objects.
// @param list the list to be populated.
// @returns true on success, false otherwise.
template <typename T>
bool LoadDiaDebugStream(IDiaEnumDebugStreamData* stream, std::vector<T>* list);

// This loads the named debug stream into the provided vector. The type T must
// be the same size as the debug stream record size. Logs any errors.
//
// @tparam T the type of object to read from the debug stream.
// @param name the name of the stream to load.
// @param dia_session the DIA session to search.
// @param list the list to be populated.
// @returns a SearchResults.
template <typename T>
SearchResult FindAndLoadDiaDebugStreamByName(const wchar_t* name,
                                             IDiaSession* dia_session,
                                             std::vector<T>* list);

}  // namespace pe

// Bring in the templated implementation details.
#include "syzygy/pe/dia_util_internal.h"

#endif  // SYZYGY_PE_DIA_UTIL_H_
