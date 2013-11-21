// Copyright 2011 Google Inc. All Rights Reserved.
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

#include <windows.h>  // NOLINT
#include <dia2.h>
#include <vector>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/win/scoped_comptr.h"

namespace pe {

// The name of the DIA SDK DLL.
extern const wchar_t kDiaDllName[];

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
// @returns true on success, false otherwise.
bool CreateDiaSession(const base::FilePath& file,
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

// Gets the symbol tab associated with the given symbol.
// @param symbol the symbol to examine.
// @param sym_tag on success, returns @p symbol's tag.
// @returns true on success, false on failure.
bool GetSymTag(IDiaSymbol* symbol, enum SymTagEnum* sym_tag);

// Checks to see if the given symbol is of the expected type.
// @returns true if @p symbol is of type @p expected_sym_tag,
//     false on error or mismatch.
bool IsSymTag(IDiaSymbol* symbol, enum SymTagEnum expected_sym_tag);

// A worker class that makes it easy to visit specific children of a given
// DIA symbol.
class ChildVisitor {
 public:
  typedef base::Callback<bool(IDiaSymbol*)> VisitSymbolCallback;

  // Creates a visitor for the children of @p parent of type @p type.
  ChildVisitor(IDiaSymbol* parent, enum SymTagEnum type);

  // Visits all children of type type, of parent symbol,
  // calling @p child_callback for each.
  // @returns true on success.
  bool VisitChildren(const VisitSymbolCallback& child_callback);

 private:
  bool VisitChildrenImpl();
  bool EnumerateChildren(IDiaEnumSymbols* children);
  bool VisitChild(IDiaSymbol* child);

  base::win::ScopedComPtr<IDiaSymbol> parent_;
  enum SymTagEnum type_;

  const VisitSymbolCallback* child_callback_;

  DISALLOW_COPY_AND_ASSIGN(ChildVisitor);
};

// A worker class that makes it easy to visit each compiland in
// in a given DIA session.
class CompilandVisitor {
 public:
  typedef ChildVisitor::VisitSymbolCallback VisitCompilandCallback;

  // Creates a visitor for all compilands of @p session.
  explicit CompilandVisitor(IDiaSession* session);

  // Visits all compilands, calling @p compiland_callback for each.
  // @returns true on success.
  bool VisitAllCompilands(const VisitCompilandCallback& compiland_callback);

 private:
  base::win::ScopedComPtr<IDiaSession> session_;

  DISALLOW_COPY_AND_ASSIGN(CompilandVisitor);
};

// A worker class that makes it easy to visit each source line record
// in a given DIA compiland.
class LineVisitor {
 public:
  typedef base::Callback<bool(IDiaLineNumber*)> VisitLineCallback;

  // Create a line visitor for the given @p session and @p compiland.
  LineVisitor(IDiaSession* session, IDiaSymbol* compiland);

  // Visit all lines records in our compiland.
  bool VisitLines(const VisitLineCallback& line_callback);

 private:
  bool VisitLinesImpl();
  bool EnumerateCompilandSource(IDiaSymbol* compiland,
                                IDiaSourceFile* source_file);
  bool EnumerateCompilandSources(IDiaSymbol* compiland,
                                 IDiaEnumSourceFiles* source_files);
  bool VisitSourceLine(IDiaLineNumber* line_number);

  base::win::ScopedComPtr<IDiaSession> session_;
  base::win::ScopedComPtr<IDiaSymbol> compiland_;

  const VisitLineCallback* line_callback_;

  DISALLOW_COPY_AND_ASSIGN(LineVisitor);
};

}  // namespace pe

// Bring in the templated implementation details.
#include "syzygy/pe/dia_util_internal.h"

#endif  // SYZYGY_PE_DIA_UTIL_H_
