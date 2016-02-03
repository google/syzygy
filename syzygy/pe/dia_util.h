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
#include "base/strings/string16.h"
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

namespace internal {

// Creates a Dia object and request an interface on it. Logs any errors.
//
// @param created_source pointer that will receive the created object.
// @param class_id the class interface ID for the object that we want to create.
// @param interface_identifier the interface ID for the object that we want to
//     create.
// @returns true on success, false otherwise.
bool CreateDiaObject(void** created_object, const CLSID& class_id,
                     const IID& interface_identifier);

}  // namespace internal

// Creates a Dia object and request an interface on it. Logs any errors.
//
// @tparam T the interface type.
// @param created_source pointer that will receive the created object.
// @param class_id the class interface ID for the object that we want to create.
// @returns true on success, false otherwise.
template <typename T>
bool CreateDiaObject(T** created_object, const CLSID& class_id);

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
// @tparam T an IDia* interface.
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

// Gets the index id associated with the given symbol.
// @param symbol the symbol to examine.
// @param sym_index_id on success, returns @p symbol's index id.
// @returns true on success, false on failure.
bool GetSymIndexId(IDiaSymbol* symbol, uint32_t* sym_index_id);

// Gets the symbol tab associated with the given symbol.
// @param symbol the symbol to examine.
// @param sym_tag on success, returns @p symbol's tag.
// @returns true on success, false on failure.
bool GetSymTag(IDiaSymbol* symbol, enum SymTagEnum* sym_tag);

// Checks to see if the given symbol is of the expected type.
// @returns true if @p symbol is of type @p expected_sym_tag,
//     false on error or mismatch.
bool IsSymTag(IDiaSymbol* symbol, enum SymTagEnum expected_sym_tag);

// Gets the name associated with the given symbol.
// @param symbol the symbol to examine.
// @param name on success, returns @p symbol's name.
// @returns true on success, false on failure.
bool GetSymName(IDiaSymbol* symbol, base::string16* name);

// Gets the undecorated name associated with the given symbol.
// @param symbol the symbol to examine.
// @param name on success, returns @p symbol's undecorated name.
// @returns true on success, false on failure.
bool GetSymUndecoratedName(IDiaSymbol* symbol, base::string16* name);

// Gets the symbol's data kind.
// @param symbol the symbol to examine.
// @param kind on success, returns @p symbol's data kind.
// @returns true on success, false on failure.
bool GetDataKind(IDiaSymbol* symbol, enum DataKind* kind);

// Gets the symbol's location type.
// @param symbol the symbol to examine.
// @param location_type on success, returns @p symbol's location type.
// @returns true on success, false on failure.
bool GetLocationType(IDiaSymbol* symbol, enum LocationType* location_type);

// Gets the symbol's register id.
// @param symbol the symbol to examine.
// @param register_id on success, returns @p symbol's register id.
// @returns true on success, false on failure.
bool GetRegisterId(IDiaSymbol* symbol, uint32_t* register_id);

// Gets the symbol's offset.
// @param symbol the symbol to examine.
// @param offset on success, returns @p symbol's offset.
// @returns true on success, false on failure.
bool GetSymOffset(IDiaSymbol* symbol, ptrdiff_t* offset);

// Gets the symbol's type.
// @param symbol the symbol to examine.
// @param type on success, returns @p symbol's type.
// @returns true on success, false on failure.
bool GetSymType(IDiaSymbol* symbol, base::win::ScopedComPtr<IDiaSymbol>* type);

// Gets the symbol's CV qualifiers.
// @param symbol the symbol to examine.
// @param is_const on success, returns whether @p symbol is const qualified.
// @param is_volatile on success, returns whether @p symbol is volatile
//     qualified.
// @returns true on success, false on failure.
bool GetSymQualifiers(IDiaSymbol* symbol, bool* is_const, bool* is_volatile);

// Gets the number of items contained by the type.
// @param symbol the symbol to examine.
// @param count on success, returns the number of items.
// @returns true on success, false on failure.
bool GetSymCount(IDiaSymbol* symbol, size_t* count);

// Gets the symbol's class parent.
// @param symbol the symbol to examine.
// @param parent on success, returns @p symbol's class parent or nullptr if the
//     parent property is no available for the symbol.
// @returns true on success, false on failure.
bool GetSymClassParent(IDiaSymbol* symbol,
                       base::win::ScopedComPtr<IDiaSymbol>* parent);

// Gets the symbol's lexical parent.
// @param symbol the symbol to examine.
// @param parent on success, returns @p symbol's lexical parent.
// @returns true on success, false on failure.
bool GetSymLexicalParent(IDiaSymbol* symbol,
                         base::win::ScopedComPtr<IDiaSymbol>* parent);

// Gets the frame's base address.
// @param frame the stack frame.
// @param frame_base on success, returns @p frame's base address.
// @returns true on sucess, false on failure.
bool GetFrameBase(IDiaStackFrame* frame, uint64_t* frame_base);

// Gets a register's value for the frame.
// @param frame the stack frame.
// @param register_index the index of the desired register.
// @param frame_base on success, returns the register's value.
// @returns true on sucess, false on failure.
bool GetRegisterValue(IDiaStackFrame* frame,
                      CV_HREG_e register_index,
                      uint64_t* register_value);

// Gets the stack frame's size.
// @param frame the stack frame.
// @param frame_size on success, returns @p frame's size.
// @returns true on sucess, false on failure.
bool GetSize(IDiaStackFrame* frame, uint32_t* frame_size);

// Gets the stack frame's locals base address.
// @param frame the stack frame.
// @param size on success, returns the base address of the locals.
// @returns true on sucess, false on failure.
bool GetLocalsBase(IDiaStackFrame* frame, uint64_t* locals_base);

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

// This macro allows the easy construction of switch statements over the
// SymTagEnum.
#define SYMTAG_CASE_TABLE(decl) \
    decl(SymTagNull) \
    decl(SymTagExe) \
    decl(SymTagCompiland) \
    decl(SymTagCompilandDetails) \
    decl(SymTagCompilandEnv) \
    decl(SymTagFunction) \
    decl(SymTagBlock) \
    decl(SymTagData) \
    decl(SymTagAnnotation) \
    decl(SymTagLabel) \
    decl(SymTagPublicSymbol) \
    decl(SymTagUDT) \
    decl(SymTagEnum) \
    decl(SymTagFunctionType) \
    decl(SymTagPointerType) \
    decl(SymTagArrayType) \
    decl(SymTagBaseType) \
    decl(SymTagTypedef) \
    decl(SymTagBaseClass) \
    decl(SymTagFriend) \
    decl(SymTagFunctionArgType) \
    decl(SymTagFuncDebugStart) \
    decl(SymTagFuncDebugEnd) \
    decl(SymTagUsingNamespace) \
    decl(SymTagVTableShape) \
    decl(SymTagVTable) \
    decl(SymTagCustom) \
    decl(SymTagThunk) \
    decl(SymTagCustomType) \
    decl(SymTagManagedType) \
    decl(SymTagDimension) \
    decl(SymTagCallSite) \
    decl(SymTagInlineSite) \
    decl(SymTagBaseInterface) \
    decl(SymTagVectorType) \
    decl(SymTagMatrixType) \
    decl(SymTagHLSLType)

}  // namespace pe

// Bring in the templated implementation details.
#include "syzygy/pe/dia_util_internal.h"

#endif  // SYZYGY_PE_DIA_UTIL_H_
