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

#include "syzygy/relink/random_relinker.h"

#include "base/file_util.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "gtest/gtest.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

using base::win::ScopedBstr;
using base::win::ScopedComPtr;
using core::RelativeAddress;

namespace relink {

namespace {

// Opens the given PDB file initializing the session and the symbols by address
// enumerator.
bool OpenPdb(const FilePath& pdb_file,
             IDiaDataSource** dia_source,
             IDiaSession** dia_session,
             IDiaEnumSymbolsByAddr** dia_symbols) {
  DCHECK(dia_source != NULL);
  DCHECK(dia_session != NULL);
  DCHECK(dia_symbols != NULL);

  if (!pe::CreateDiaSource(dia_source) ||
      !pe::CreateDiaSession(pdb_file, *dia_source, dia_session)) {
    return false;
  }

  HRESULT hr = (*dia_session)->getSymbolsByAddr(dia_symbols);
  if (FAILED(hr))
    return false;
  DCHECK(*dia_symbols != NULL);

  return true;
}

// Checks if two symbols are equivalent, and if their addresses agree with those
// we expect them to have.
bool SymbolsAreEquivalent(RelativeAddress rva1,
                          RelativeAddress rva2,
                          IDiaSymbol* symbol1,
                          IDiaSymbol* symbol2) {
  // Get all of the properties from each symbol.
  DWORD section1 = 0, section2 = 0;
  DWORD offset1 = 0, offset2 = 0;
  DWORD addr1 = 0, addr2 = 0;
  ULONGLONG length1 = 0, length2 = 0;
  ScopedBstr name1, name2;
  if (FAILED(symbol1->get_addressSection(&section1)) ||
      FAILED(symbol1->get_addressOffset(&offset1)) ||
      FAILED(symbol1->get_relativeVirtualAddress(&addr1)) ||
      FAILED(symbol1->get_length(&length1)) ||
      FAILED(symbol1->get_name(name1.Receive()))) {
    return false;
  }
  if (FAILED(symbol2->get_addressSection(&section2)) ||
      FAILED(symbol2->get_addressOffset(&offset2)) ||
      FAILED(symbol2->get_relativeVirtualAddress(&addr2)) ||
      FAILED(symbol2->get_length(&length2)) ||
      FAILED(symbol2->get_name(name2.Receive()))) {
    return false;
  }

  // Compare the properties.
  if (rva1.value() != addr1 || rva2.value() != addr2 ||
      section1 != section2 || offset1 != offset2 ||
      length1 != length2 ||
      name1.ByteLength() != name2.ByteLength() ||
      memcmp(static_cast<BSTR>(name1), static_cast<BSTR>(name2),
             name1.ByteLength()) != 0) {
    return false;
  }

  return true;
}

// Reads OMAP vectors from the given DIA session. Expects both OMAP vectors
// to exist.
bool ReadOmapVectors(IDiaSession* dia_session,
                     std::vector<OMAP>* omap_to,
                     std::vector<OMAP>* omap_from) {
  DCHECK(dia_session != NULL);
  DCHECK(omap_to != NULL);
  DCHECK(omap_from != NULL);

  pe::SearchResult search_result = pe::FindAndLoadDiaDebugStreamByName(
      pe::kOmapToDiaDebugStreamName, dia_session, omap_to);
  if (search_result != pe::kSearchSucceeded)
    return false;

  search_result = pe::FindAndLoadDiaDebugStreamByName(
      pe::kOmapFromDiaDebugStreamName, dia_session, omap_from);
  return search_result == pe::kSearchSucceeded;
}

// Validates the provided OMAP vector that maps between addresses in the image
// covered by the first PDB and those in the image covered by the second PDB.
bool OmapIsGoodInOneDirection(const std::vector<OMAP>& omap,
                              IDiaEnumSymbolsByAddr* dia_symbols1,
                              IDiaEnumSymbolsByAddr* dia_symbols2) {
  // Iterate through all of the symbols in the first PDB.
  ScopedComPtr<IDiaSymbol> dia_symbol1;

  // Start with the symbol at the beginning of the first section.
  if (FAILED(dia_symbols1->symbolByAddr(1, 0, dia_symbol1.Receive())))
    return false;

  while (true) {
    ScopedComPtr<IDiaSymbol> dia_symbol2;
    DWORD dwrva1;
    if (FAILED(dia_symbol1->get_relativeVirtualAddress(&dwrva1)))
      return false;

    // We skip symbols with a null relative address. These symbols appear as
    // noise in the SymbolsByAddr enumeration.
    if (dwrva1 != 0) {
      // Get this symbols address in the second image by manually mapping
      // through the OMAP information.
      RelativeAddress rva1(dwrva1);
      RelativeAddress rva2 = pdb::TranslateAddressViaOmap(omap, rva1);

      // Get the corresponding symbol in the second image.
      if (FAILED(dia_symbols2->symbolByRVA(rva2.value(),
                                           dia_symbol2.Receive()))) {
        return false;
      }

      // Compare the symbols.
      if (!SymbolsAreEquivalent(
          rva1, rva2, dia_symbol1.get(), dia_symbol2.get())) {
        return false;
      }
    }

    // Get the next symbol.
    dia_symbol1.Release();
    ULONG fetched = 0;
    HRESULT hr = dia_symbols1->Next(1, dia_symbol1.Receive(), &fetched);
    if (hr == S_FALSE)  // This happens when there are no more symbols.
      break;
    if (FAILED(hr) || fetched != 1)
      return false;
  }

  return true;
}

// Tests if the OMAP information in the second PDB file is accurate. This
// doesn't guarantee that it is accurate wrt the relinked image, but rather that
// the OMAP works the way we think it does; both us and DIA use it in the same
// way and come to the same results.
//
// We do this by iterating through all symbols in the original PDB, and manually
// mapping them via the OMAPFROM information of the second PDB into an address
// in the relinked image. We then ask DIA to retrieve the symbol at that
// address. DIA will use OMAPTO to convert it back to an address in the original
// image and return that symbol. The two symbols should be one and the same.
//
// To ensure the mapping is symmetric we also do the same thing in the other
// direction, iterating the relinked PDB.
bool OmapIsGood(const FilePath& input_pdb_path,
                const FilePath& output_pdb_path) {
  ScopedComPtr<IDiaDataSource> dia_source1, dia_source2;
  ScopedComPtr<IDiaSession> dia_session1, dia_session2;
  ScopedComPtr<IDiaEnumSymbolsByAddr> dia_symbols1, dia_symbols2;

  if (!OpenPdb(input_pdb_path,
               dia_source1.Receive(),
               dia_session1.Receive(),
               dia_symbols1.Receive())) {
    return false;
  }

  if (!OpenPdb(output_pdb_path,
               dia_source2.Receive(),
               dia_session2.Receive(),
               dia_symbols2.Receive())) {
    return false;
  }

  std::vector<OMAP> omap_to, omap_from;
  if (!ReadOmapVectors(dia_session2.get(), &omap_to, &omap_from))
    return false;

  // Test the OMAPFROM map.
  if (!OmapIsGoodInOneDirection(omap_from, dia_symbols1, dia_symbols2))
    return false;

  // Test the OMAPTO map.
  if (!OmapIsGoodInOneDirection(omap_to, dia_symbols2, dia_symbols1))
    return false;

  return true;
}

}  // namespace

class RandomRelinkerTest : public testing::PELibUnitTest {
  // Put any specializations here
};

TEST_F(RandomRelinkerTest, Relink) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath output_dll_path = temp_dir.Append(kDllName);
  FilePath output_pdb_path = temp_dir.Append(kDllPdbName);

  RandomRelinker relinker(12345);
  ASSERT_TRUE(relinker.Relink(GetExeRelativePath(kDllName),
                              GetExeRelativePath(kDllPdbName),
                              output_dll_path,
                              output_pdb_path,
                              true));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));

  CheckEmbeddedPdbPath(output_dll_path, output_pdb_path);

  // Ensure that the PDB file pre- and post- transform agrees. That is, that the
  // OMAP information is accurate and complete.
  // TODO(chrisha): This should eventually be its own unittest. We could add
  //    a target to test_data.gyp that creates a randomly relinked version of
  //    test_dll, and this could compare the two generated PDBs.
  ASSERT_TRUE(OmapIsGood(GetExeRelativePath(kDllPdbName), output_pdb_path));
}

TEST_F(RandomRelinkerTest, RelinkWithPadding) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath output_dll_path = temp_dir.Append(kDllName);
  FilePath output_pdb_path = temp_dir.Append(kDllPdbName);

  RandomRelinker relinker(56789);
  relinker.set_padding_length(32);
  ASSERT_TRUE(relinker.Relink(GetExeRelativePath(kDllName),
                              GetExeRelativePath(kDllPdbName),
                              output_dll_path,
                              output_pdb_path,
                              true));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));

  CheckEmbeddedPdbPath(output_dll_path, output_pdb_path);

  ASSERT_TRUE(OmapIsGood(GetExeRelativePath(kDllPdbName), output_pdb_path));
}

}  // namespace relink
