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
#include "syzygy/reorder/comdat_order.h"

#include <cvconst.h>
#include <diacreate.h>
#include <stdio.h>
#include "base/bind.h"
#include "base/file_util.h"
#include "base/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "sawbuck/common/com_utils.h"

namespace reorder {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;
using pe::DiaBrowser;

namespace {

// Creates a DIA data source.
// TODO(chrisha): Move this functionality to DiaBrowser, and also remove it
//     from Decomposer.
bool CreateDiaSource(IDiaDataSource** created_source) {
  ScopedComPtr<IDiaDataSource> dia_source;
  HRESULT hr = dia_source.CreateInstance(CLSID_DiaSource);
  if (SUCCEEDED(hr)) {
    *created_source = dia_source.Detach();
    return true;
  }

  VLOG(1) << "CoCreate failed: " << com::LogHr(hr)
          << ". Falling back to NoRegCoCreate.";

  hr = NoRegCoCreate(L"msdia90.dll",
                     CLSID_DiaSource,
                     IID_IDiaDataSource,
                     reinterpret_cast<void**>(&dia_source));
  if (SUCCEEDED(hr)) {
    *created_source = dia_source.Detach();
    return true;
  }

  LOG(ERROR) << "NoRegCoCreate failed: " << com::LogHr(hr);

  return false;
}

}

ComdatOrder::ComdatOrder(const FilePath& input_dll)
    : input_dll_(input_dll) {
}

bool ComdatOrder::LoadSymbols() {
  if (!image_file_.Init(input_dll_)) {
    LOG(ERROR) << "Unable to parse module signature: "
               << input_dll_.value();
    return false;
  }

  if (!InitDia())
    return false;

  DiaBrowser dia_browser;
  DiaBrowser::MatchCallback on_public_symbol(
      base::Bind(&ComdatOrder::OnPublicSymbol, base::Unretained(this)));
  if (!dia_browser.AddPattern(SymTagPublicSymbol, on_public_symbol))
    return false;

  comdats_.clear();
  return dia_browser.Browse(dia_global_);
}

bool ComdatOrder::OutputOrder(const FilePath& path,
                              const Reorderer::Order& order) {
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open for writing: " << path.value();
    return false;
  }

  // Mark all COMDATs as not having been output.
  ComdatMap::iterator comdat_it = comdats_.begin();
  ComdatMap::iterator comdat_end = comdats_.end();
  for (; comdat_it != comdat_end; ++comdat_it)
    comdat_it->second.second = false;

  size_t comdats_written = 0;
  size_t blocks_without_comdats = 0;
  size_t blocks_with_comdats = 0;

  // Iterate through the sections.
  size_t section_count = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t section_id = 0; section_id < section_count; ++section_id) {
    const IMAGE_SECTION_HEADER* section_header =
        image_file_.section_header(section_id);
    RelativeAddress section_start(section_header->VirtualAddress);
    RelativeAddress section_end = section_start +
                                  section_header->Misc.VirtualSize;

    // If this section has explicit ordering information, dump the COMDATs
    // according to the order.
    Reorderer::Order::BlockListMap::const_iterator section_it =
        order.section_block_lists.find(section_id);
    if (section_it != order.section_block_lists.end()) {
      Reorderer::Order::BlockList::const_iterator block_it =
          section_it->second.begin();
      for (; block_it != section_it->second.end(); ++block_it) {
        // Get the start and end addresses of the block.
        RelativeAddress block_start = (*block_it)->addr();
        RelativeAddress block_end = block_start + (*block_it)->size();

        // Find the COMDATs that lie within this block.
        comdat_it = comdats_.lower_bound(block_start);
        comdat_end = comdats_.lower_bound(block_end);

        if (comdat_it == comdat_end)
          ++blocks_without_comdats;
        else
          ++blocks_with_comdats;

        // Iterate through the COMDATs, and dump them to the file, marking
        // which ones we've already output.
        for (; comdat_it != comdat_end; ++comdat_it) {
          DCHECK_EQ(false, comdat_it->second.second);
          if (fprintf(file.get(), "%s\n",
                      comdat_it->second.first.c_str()) < 0) {
            LOG(ERROR) << "Error writing to file: " << path.value();
            return false;
          }
          ++comdats_written;
          comdat_it->second.second = true;
        }
      }

      // Now output all the other comdats for this section that have not been
      // explicitly ordered.
      comdat_it = comdats_.lower_bound(section_start);
      comdat_end = comdats_.lower_bound(section_end);
      for (; comdat_it != comdat_end; ++comdat_it) {
        if (comdat_it->second.second)
          continue;
        if (fprintf(file.get(), "%s\n", comdat_it->second.first.c_str()) < 0) {
          LOG(ERROR) << "Error writing to file: " << path.value();
          return false;
        }
        ++comdats_written;
        comdat_it->second.second = true;
      }
    }
  }

  // Finally, output all remaining COMDATs.
  comdat_it = comdats_.begin();
  comdat_end = comdats_.end();
  for (; comdat_it != comdat_end; ++comdat_it) {
    if (comdat_it->second.second)
      continue;
    if (fprintf(file.get(), "%s\n", comdat_it->second.first.c_str()) < 0) {
      LOG(ERROR) << "Error writing to file: " << path.value();
      return false;
    }
    ++comdats_written;
    comdat_it->second.second = true;
  }

  DCHECK_EQ(comdats_written, comdats_.size());

  return true;
}

ComdatOrder::ComdatOrder() {
}

bool ComdatOrder::InitDia() {
  if (!CreateDiaSource(dia_source_.Receive())) {
    LOG(ERROR) << "Failed to create DIA source object.";
    return false;
  }

  HRESULT hr = dia_source_->loadDataForExe(input_dll_.value().c_str(),
                                           NULL,
                                           NULL);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to load DIA data for file: " << com::LogHr(hr);
    return false;
  }

  hr = dia_source_->openSession(dia_session_.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to open DIA session: " << com::LogHr(hr);
    return false;
  }

  hr = dia_session_->get_globalScope(dia_global_.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA global scope: " << com::LogHr(hr);
    return false;
  }

  return true;
}

void ComdatOrder::OnPublicSymbol(const DiaBrowser& dia_browser,
                                 const DiaBrowser::SymTagVector& sym_tags,
                                 const DiaBrowser::SymbolPtrVector& symbols,
                                 DiaBrowser::BrowserDirective* directive) {
  DCHECK(*directive == DiaBrowser::kBrowserContinue);

  DWORD rva = 0;
  ScopedBstr name;
  DiaBrowser::SymbolPtr symbol = symbols.back();
  if (FAILED(symbol->get_relativeVirtualAddress(&rva)) ||
      FAILED(symbol->get_name(name.Receive()))) {
    LOG(ERROR) << "Failed to retrieve public symbol information.";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }

  RelativeAddress address(rva);

  std::string comdat_name;
  if (!WideToUTF8(name, name.Length(), &comdat_name)) {
    LOG(ERROR) << "Failed to convert public symbol name to UTF8.";
    *directive = DiaBrowser::kBrowserAbort;
    return;
  }

  DCHECK(comdat_name.size() > 0);

  // Remove a single leading '_', if present, as per:
  // http://msdn.microsoft.com/en-us/library/00kh39zz(v=vs.80).aspx
  if (comdat_name[0] == '_')
    comdat_name = comdat_name.substr(1);

  comdats_[address] = std::make_pair(comdat_name, false);
}

}  // namespace reorder
