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

#include "syzygy/grinder/line_info.h"

#include <dia2.h>
#include <algorithm>
#include <limits>

#include "base/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/address_space.h"

namespace grinder {

namespace {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

typedef core::AddressRange<core::RelativeAddress, size_t> RelativeAddressRange;
typedef std::map<DWORD, const std::string*> SourceFileMap;

bool GetDiaSessionForPdb(const base::FilePath& pdb_path,
                         IDiaDataSource* source,
                         IDiaSession** session) {
  DCHECK(source != NULL);
  DCHECK(session != NULL);

  HRESULT hr = source->loadDataFromPdb(pdb_path.value().c_str());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in loadDataFromPdb: " << common::LogHr(hr) << ".";
    return false;
  }

  hr = source->openSession(session);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in openSession: " << common::LogHr(hr) << ".";
    return false;
  }

  return true;
}


bool DisableOmapTranslation(IDiaSession* session) {
  DCHECK(session != NULL);

  ScopedComPtr<IDiaAddressMap> addr_map;
  HRESULT hr = session->QueryInterface(IID_IDiaAddressMap,
                                       addr_map.ReceiveVoid());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in QueryInterface: " << common::LogHr(hr) << ".";
    return false;
  }
  hr = addr_map->put_addressMapEnabled(FALSE);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in put_addressMapEnabled: " << common::LogHr(hr)
               << ".";
    return false;
  }

  return true;
}

const std::string* GetSourceFileName(DWORD source_file_id,
                                     IDiaLineNumber* line_number,
                                     LineInfo::SourceFileSet* source_files,
                                     SourceFileMap* source_file_map) {
  DCHECK(line_number != NULL);
  DCHECK(source_files != NULL);
  DCHECK(source_file_map != NULL);

  SourceFileMap::const_iterator map_it = source_file_map->find(source_file_id);

  if (map_it != source_file_map->end())
    return map_it->second;

  ScopedComPtr<IDiaSourceFile> source_file;
  HRESULT hr = line_number->get_sourceFile(source_file.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_sourceFile: " << common::LogHr(hr) << ".";
    return NULL;
  }

  ScopedBstr source_file_path_bstr;
  hr = source_file->get_fileName(source_file_path_bstr.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_fileName: " << common::LogHr(hr) << ".";
    return NULL;
  }

  std::string source_file_path;
  if (!WideToUTF8(common::ToString(source_file_path_bstr),
                  source_file_path_bstr.Length(),
                  &source_file_path)) {
    LOG(ERROR) << "WideToUTF8 failed for path \""
               << common::ToString(source_file_path_bstr) << "\".";
    return NULL;
  }

  LineInfo::SourceFileSet::const_iterator source_file_it =
      source_files->insert(source_file_path).first;
  const std::string* source_file_name = &(*source_file_it);
  source_file_map->insert(std::make_pair(source_file_id,
                                         source_file_name));

  return source_file_name;
}

// Used for comparing the ranges covered by two source lines.
struct SourceLineAddressComparator {
  bool operator()(const LineInfo::SourceLine& sl1,
                  const LineInfo::SourceLine& sl2) const {
    return sl1.address + sl1.size <= sl2.address;
  }
};

}  // namespace

bool LineInfo::Init(const base::FilePath& pdb_path) {
  ScopedComPtr<IDiaDataSource> source;
  HRESULT hr = source.CreateInstance(CLSID_DiaSource);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to create DiaSource: " << common::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSession> session;
  if (!GetDiaSessionForPdb(pdb_path, source.get(), session.Receive()))
    return false;

  // We want original module addresses so we disable OMAP translation.
  if (!DisableOmapTranslation(session.get()))
    return false;

  // Get the line number enumeration.
  ScopedComPtr<IDiaEnumLineNumbers> line_number_enum;
  hr = session->findLinesByRVA(0, 0xFFFFFF, line_number_enum.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in findLinesByRVA: " << common::LogHr(hr) << ".";
    return false;
  }

  // A map of source file IDs we've already seen, mapping back to the source
  // file path. We use this as a cache so we're not constantly doing source-file
  // lookups while iterating.
  SourceFileMap source_file_map;

  // Get the line info count and reserve space.
  LONG line_number_count = 0;
  hr = line_number_enum->get_Count(&line_number_count);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_Count: " << common::LogHr(hr) << ".";
    return false;
  }
  source_lines_.reserve(line_number_count);

  // Iterate over the source line information.
  DWORD old_source_file_id = -1;
  DWORD old_rva = 0;
  const std::string* source_file_name = NULL;
  while (true) {
    ScopedComPtr<IDiaLineNumber> line_number;
    ULONG fetched = 0;
    hr = line_number_enum->Next(1, line_number.Receive(), &fetched);
    if (hr != S_OK || fetched != 1)
      break;

    DWORD source_file_id = 0;
    hr = line_number->get_sourceFileId(&source_file_id);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failure in get_sourceFileId: " << common::LogHr(hr) << ".";
      return false;
    }

    // Look for the source file by ID. Since we most often see successive
    // lines from the same file we have a shortcut to avoid extra processing in
    // this case.
    if (source_file_id != old_source_file_id) {
      source_file_name = GetSourceFileName(source_file_id,
                                           line_number.get(),
                                           &source_files_,
                                           &source_file_map);
    }
    old_source_file_id = source_file_id;
    DCHECK(source_file_name != NULL);

    DWORD line = 0;
    DWORD rva = 0;
    DWORD length = 0;
    if (FAILED(line_number->get_lineNumber(&line)) ||
        FAILED(line_number->get_relativeVirtualAddress(&rva)) ||
        FAILED(line_number->get_length(&length))) {
      LOG(ERROR) << "Failed to get line number properties.";
      return false;
    }

    // We rely on the enumeration returning us lines in order of increasing
    // address, as they are stored originally in the PDB. This is required for
    // the following zero-length fixing mechanism to work as intended.
    DCHECK_LE(old_rva, rva);
    old_rva = rva;

    // Is this a non-zero length? Back up and make any zero-length ranges
    // with the same start address the same length as us. This makes them
    // simply look like repeated entries in the array and makes searching for
    // them with lower_bound/upper_bound work as expected.
    if (length != 0) {
      SourceLines::reverse_iterator it = source_lines_.rbegin();
      for (; it != source_lines_.rend(); ++it) {
        if (it->size != 0)
          break;
        if (it->address.value() != rva) {
          LOG(ERROR) << "Encountered zero-length line number with "
                     << "inconsistent address.";
          return false;
        }
        it->size = length;
      }
    }

    source_lines_.push_back(SourceLine(source_file_name,
                                       line,
                                       core::RelativeAddress(rva),
                                       length));
  }

  return true;
}

bool LineInfo::Visit(
    core::RelativeAddress address, size_t size, size_t count) {
  // Visiting a range of size zero is a nop.
  if (size == 0)
    return true;

  // Create a dummy 'source line' for the search.
  SourceLine visit_source_line(NULL, 0, address, size);

  SourceLines::iterator begin_it =
      std::lower_bound(source_lines_.begin(),
                       source_lines_.end(),
                       visit_source_line,
                       SourceLineAddressComparator());

  SourceLines::iterator end_it =
      std::upper_bound(source_lines_.begin(),
                       source_lines_.end(),
                       visit_source_line,
                       SourceLineAddressComparator());

  SourceLines::iterator it = begin_it;
  RelativeAddressRange visit(address, size);
  for (; it != end_it; ++it) {
    RelativeAddressRange range(it->address, it->size);
    if (visit.Intersects(range)) {
      // We use saturation arithmetic here as overflow is a real possibility in
      // long trace files.
      it->visit_count =
          std::min(it->visit_count,
                   std::numeric_limits<uint32>::max() - count) + count;
    }
  }

  return true;
}

}  // namespace grinder
