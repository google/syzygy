// Copyright 2009 Google Inc.
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
#include "sawbuck/sym_util/symbol_cache.h"

#include "base/strings/string_util.h"
#include <dbghelp.h>

namespace {

template <size_t name_len>
class SymbolInfo {
 public:
  SymbolInfo() {
    memset(buf_, 0, sizeof(buf_));
    info_.SizeOfStruct = sizeof(info_);
    info_.MaxNameLen = name_len;
  }
  PSYMBOL_INFO get() {
    return &info_;
  }

 private:
  union {
    SYMBOL_INFO info_;
    char buf_[offsetof(SYMBOL_INFO, Name) + name_len * sizeof(wchar_t)];
  };
};

}  // namespace

namespace sym_util {

SymbolCache::SymbolCache() : initialized_(false) {
  // We use our own this pointer as process handle to ensure uniqueness
  // of handles passed to SymInitialize within our process.
  process_handle_ = reinterpret_cast<HANDLE>(this);
  DWORD options = ::SymGetOptions();

  // Defer loading symbols until they're needed.
  options |= SYMOPT_DEFERRED_LOADS | SYMOPT_EXACT_SYMBOLS | SYMOPT_DEBUG;
  ::SymSetOptions(options);
}

SymbolCache::~SymbolCache() {
  Cleanup();
}

bool SymbolCache::Initialize(size_t num_modules,
                             ModuleInformation* modules) {
  const wchar_t* symbol_path = NULL;
  if (!symbol_path_.empty())
    symbol_path = symbol_path_.c_str();

  if (!::SymInitialize(process_handle_, symbol_path, FALSE))
    return false;

  ::SymRegisterCallback64(process_handle_,
                          SymbolCallback,
                          reinterpret_cast<ULONG64>(this));

  initialized_ = true;

  // Load the modules.
  for (size_t i = 0; i < num_modules; ++i) {
    modules_.push_back(modules[i]);

    DWORD64 load_base = ::SymLoadModuleEx(process_handle_,
                                          NULL,
                                          modules[i].image_file_name.c_str(),
                                          NULL,
                                          modules[i].base_address,
                                          modules[i].module_size,
                                          NULL,
                                          0);
  }

  return true;
}

bool SymbolCache::GetSymbolForAddress(Address address, Symbol *symbol) {
  // Try the local cache first.
  SymbolMap::const_iterator it(cache_.find(address));
  if (it != cache_.end()) {
    *symbol = it->second;
    return true;
  }

  IMAGEHLP_MODULE64 module = { sizeof(module) };
  if (::SymGetModuleInfo64(process_handle_, address, &module)) {
    symbol->module = module.ImageName;
    symbol->module_base = module.BaseOfImage;
  }

  DWORD64 offset = 0;
  SymbolInfo<1024> sym_info;
  if (!::SymFromAddr(process_handle_, address, &offset, sym_info.get()))
    return false;

  symbol->name = sym_info.get()->Name;
  symbol->offset = static_cast<size_t>(offset);
  symbol->size = sym_info.get()->Size;

  // Lookup the unmagled name.
  DWORD options = ::SymGetOptions();
  ::SymSetOptions((options | SYMOPT_PUBLICS_ONLY) & ~SYMOPT_UNDNAME);
  if (::SymFromAddr(process_handle_, address, &offset, sym_info.get()))
    symbol->mangled_name = sym_info.get()->Name;
  ::SymSetOptions(options);

  IMAGEHLP_LINE64 line_info = { sizeof(line_info) };
  DWORD line_displacement = 0;
  if (::SymGetLineFromAddr64(process_handle_,
                             address,
                             &line_displacement,
                             &line_info)) {
    symbol->file = line_info.FileName;
    symbol->line = line_info.LineNumber;
  }

  cache_.insert(std::make_pair(address, *symbol));
  return true;
}

void SymbolCache::Cleanup() {
  if (initialized_)
    ::SymCleanup(process_handle_);

  initialized_ = false;
}

void SymbolCache::SetSymbolPath(const wchar_t* symbol_path) {
  if (symbol_path != NULL)
    symbol_path_ = symbol_path;
  else
    symbol_path_ = L"";

  if (initialized_) {
    // Switch the symbol path to the newly supplied one.
    ::SymSetSearchPath(process_handle_, symbol_path);

    // And flush the cache.
    cache_.clear();
  }
}

// TODO(siggi): This callback needs cleaning up. Firstly anytime it sees
//    a proposed module, or when it thinks it's found a match in e.g.
//    systemroot or by prepending a drive letter, or whathever, it should
//    check that the module size, checksum and timestamp match.
//    Secondly, this really ought to be wired up to the status pane,
//    to let the user know whenever there's a potentially long-running
//    operation in progress.
BOOL CALLBACK SymbolCache::SymbolCallback(HANDLE process,
                                          ULONG action,
                                          ULONG64 data,
                                          ULONG64 context) {
  SymbolCache* cache = reinterpret_cast<SymbolCache*>(context);

  switch (action) {
    case CBA_DEBUG_INFO:
      LOG(INFO) << "CBA_DEBUG_INFO(" << reinterpret_cast<const wchar_t*>(data)
          << ")";
      break;

    case CBA_DEFERRED_SYMBOL_LOAD_CANCEL:
      // This is invoked a lot to query whether we'd like to cancel
      // out of the current symbol download.
      break;

    case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE: {
      IMAGEHLP_DEFERRED_SYMBOL_LOAD64* loaded =
          reinterpret_cast<IMAGEHLP_DEFERRED_SYMBOL_LOAD64*>(data);
      if (!cache->status_callback_.is_null()) {
        std::wstring status(L"Loaded ");
        status.append(loaded->FileName);
        cache->status_callback_.Run(status.c_str());
      }
      break;
    }

    case CBA_DEFERRED_SYMBOL_LOAD_FAILURE: {
      IMAGEHLP_DEFERRED_SYMBOL_LOAD64* loaded =
          reinterpret_cast<IMAGEHLP_DEFERRED_SYMBOL_LOAD64*>(data);
      LOG(INFO) << "CBA_DEFERRED_SYMBOL_LOAD_FAILURE(0x\n" <<
          loaded->BaseOfImage << ")";
      break;
    }

    case CBA_DEFERRED_SYMBOL_LOAD_PARTIAL: {
      IMAGEHLP_DEFERRED_SYMBOL_LOAD64* loaded =
          reinterpret_cast<IMAGEHLP_DEFERRED_SYMBOL_LOAD64*>(data);
      LOG(INFO) << "CBA_DEFERRED_SYMBOL_LOAD_PARTIAL(" << loaded->FileName
          << ")";

      ModuleInformation info;
      if (cache->GetModuleInformation(loaded->BaseOfImage, &info)) {
        loaded->CheckSum = info.image_checksum;
        loaded->TimeDateStamp = info.time_date_stamp;
        loaded->Reparse = TRUE;
        return TRUE;
      }
      break;
    }

    case CBA_DEFERRED_SYMBOL_LOAD_START: {
      IMAGEHLP_DEFERRED_SYMBOL_LOAD64* loaded =
          reinterpret_cast<IMAGEHLP_DEFERRED_SYMBOL_LOAD64*>(data);
      LOG(INFO) << "CBA_DEFERRED_SYMBOL_LOAD_START(0x" << loaded->BaseOfImage
          << ")\n";
      break;
    }

    case CBA_DUPLICATE_SYMBOL:
      LOG(INFO) << "CBA_DUPLICATE_SYMBOL";
      break;

    case CBA_EVENT: {
      IMAGEHLP_CBA_EVENT* event = reinterpret_cast<IMAGEHLP_CBA_EVENT*>(data);
      LOG(INFO) << "CBA_EVENT(" << std::hex << event->code << ", "
          << event->desc << ")";
      if (!cache->status_callback_.is_null())
        cache->status_callback_.Run(event->desc);
      break;
    }

    case CBA_READ_MEMORY: {
      IMAGEHLP_CBA_READ_MEMORY* read_mem =
          reinterpret_cast<IMAGEHLP_CBA_READ_MEMORY*>(data);
      LOG(INFO) << "CBA_READ_MEMORY("
          << reinterpret_cast<void*>(read_mem->addr) << ", "
          << read_mem->bytes;
      break;
    }

    case CBA_SET_OPTIONS:
      LOG(INFO) << "CBA_SET_OPTIONS";
      break;

// The SDK does not (yet) define these constants and structures.
#if 0
    case CBA_SRCSRV_EVENT: {
      IMAGEHLP_CBA_EVENT* event = reinterpret_cast<IMAGEHLP_CBA_EVENT*>(data);
      ATLTRACE(L"CBA_SRCSRV_EVENT(0x%08X, %s)\n", event->code, event->desc);
      break;
    }

    case CBA_SRCSRV_INFO: {
      ATLTRACE(L"CBA_SRCSRV_INFO: %s\n", reinterpret_cast<const char*>(data));
      break;
    }
#endif

    case CBA_SYMBOLS_UNLOADED:
      LOG(INFO) << "CBA_SYMBOLS_UNLOADED";
      break;
  }

  return false;
}

bool SymbolCache::GetModuleInformation(Address load_address,
                                       ModuleInformation* info) {
  for (size_t i = 0; i < modules_.size(); ++i) {
    if (modules_[i].base_address == load_address) {
      *info = modules_[i];
      return true;
    }
  }

  return false;
}

}  // namespace sym_util
