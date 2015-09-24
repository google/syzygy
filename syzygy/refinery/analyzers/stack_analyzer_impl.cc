// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/stack_analyzer_impl.h"

#include <algorithm>
#include <string>
#include <vector>

#include "base/environment.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/refinery/core/addressed_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {
namespace {

// TODO(manzagop): this probably exists somewhere?
bool GetEnvVar(const char* name, std::wstring* value) {
  DCHECK(name != NULL);
  DCHECK(value != NULL);
  value->clear();

  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string var;
  if (!env->GetVar(name, &var))
    return true;

  if (!base::UTF8ToWide(var.c_str(), var.size(), value)) {
    LOG(ERROR) << "base::UTF8ToWide(\"" << var << "\" failed.";
    return false;
  }

  return true;
}

bool GetModuleSignature(ModuleRecordPtr module_record,
                        scoped_ptr<pe::PEFile::Signature>* signature) {
  DCHECK(signature);

  const AddressRange& module_range = module_record->range();
  const Module& module = module_record->data();

  // Get the module's path.
  const std::string& module_path = module.name();
  base::string16 module_path_wide;
  if (!base::UTF8ToUTF16(module_path.c_str(), module_path.size(),
                         &module_path_wide)) {
    LOG(ERROR) << "base::UTF8ToUTF16(\"" << module_path << "\" failed.";
    return false;
  }

  // Get the module's address.
  if (!base::IsValueInRangeForNumericType<uint32>(module_range.start())) {
    LOG(ERROR) << "PE::Signature doesn't support 64bit addresses. Address: "
               << module_range.start();
    return false;
  }
  pe::PEFile::AbsoluteAddress module_address(
      base::checked_cast<uint32>(module_range.start()));

  signature->reset(new pe::PEFile::Signature(
      module_path_wide, module_address, module_range.size(), module.checksum(),
      module.timestamp()));
  return true;
}

bool GetPdbPath(const pe::PEFile::Signature& signature,
                base::FilePath* pdb_path) {
  DCHECK(pdb_path);

  // Get the module's path.
  std::wstring symbol_paths;
  GetEnvVar("_NT_SYMBOL_PATH", &symbol_paths);
  base::FilePath module_local_path;
  if (!pe::FindModuleBySignature(signature, symbol_paths, &module_local_path) ||
      module_local_path.empty()) {
    LOG(ERROR) << "Failed to find module (name, size, timestamp): "
               << signature.path << ", " << signature.module_size << ", "
               << signature.module_time_date_stamp;
    return false;
  }

  // Get the pdb's path.
  if (!pe::FindPdbForModule(module_local_path, symbol_paths, pdb_path) ||
      pdb_path->empty()) {
    LOG(ERROR) << "Failed to find pdb for module " << signature.path;
    return false;
  }

  return true;
}

}  // namespace

StackWalkHelper::StackWalkHelper() {
  registers_.clear();
}

StackWalkHelper::~StackWalkHelper() {
}

void StackWalkHelper::SetState(StackRecordPtr stack_record,
                               ProcessState* process_state) {
  // Set up the context. For the excepting thread, we use the exception's
  // context.
  // TODO(manzagop): consider walking stack from all available contexts and
  // merging the walks.
  registers_.clear();
  DCHECK(stack_record->data().has_thread_info());
  const ThreadInformation& thread_info = stack_record->data().thread_info();
  const RegisterInformation* context;
  if (thread_info.has_exception()) {
    context = &thread_info.exception().register_info();
  } else {
    context = &thread_info.register_info();
  }

  // Set registers that are handled.
  // TODO(manzagop): should the the allreg registers also be set?
  put_registerValue(CV_REG_GS, context->seg_gs());
  put_registerValue(CV_REG_FS, context->seg_fs());
  put_registerValue(CV_REG_ES, context->seg_es());
  put_registerValue(CV_REG_DS, context->seg_ds());
  put_registerValue(CV_REG_EDI, context->edi());
  put_registerValue(CV_REG_ESI, context->esi());
  put_registerValue(CV_REG_EBX, context->ebx());
  put_registerValue(CV_REG_EDX, context->edx());
  put_registerValue(CV_REG_ECX, context->ecx());
  put_registerValue(CV_REG_EAX, context->eax());
  put_registerValue(CV_REG_EBP, context->ebp());
  put_registerValue(CV_REG_EIP, context->eip());
  put_registerValue(CV_REG_CS, context->seg_cs());
  put_registerValue(CV_REG_EFLAGS, context->eflags());
  put_registerValue(CV_REG_ESP, context->esp());
  put_registerValue(CV_REG_SS, context->seg_ss());

  // Set the process state.
  process_state_ = process_state;
}

STDMETHODIMP_(ULONG) StackWalkHelper::AddRef() {
  return base::win::IUnknownImpl::AddRef();
}

STDMETHODIMP_(ULONG) StackWalkHelper::Release() {
  return base::win::IUnknownImpl::Release();
}

STDMETHODIMP StackWalkHelper::QueryInterface(REFIID riid, PVOID* ptr_void) {
  DCHECK(ptr_void);

  if (riid == __uuidof(IDiaStackWalkHelper)) {
    *ptr_void = static_cast<IDiaStackWalkHelper*>(this);
    AddRef();
    return S_OK;
  } else {
    // Know it if another interface is requested.
    const int kGUIDSize = 39;
    std::wstring riid_str;
    int result =
        StringFromGUID2(riid, base::WriteInto(&riid_str, kGUIDSize), kGUIDSize);
    DCHECK_GT(result, 0);
    LOG(ERROR) << base::StringPrintf(L"StackWalkHelper::QueryInterface for %ls",
                                     riid_str.c_str());
    DCHECK(false);
    return base::win::IUnknownImpl::QueryInterface(riid, ptr_void);
  }
}

STDMETHODIMP StackWalkHelper::get_registerValue(DWORD index,
                                                ULONGLONG* pRetVal) {
  if (!pRetVal) {
    return E_INVALIDARG;
  }

  // Only support retrieval of registers that were previously set.
  const auto it = registers_.find(static_cast<CV_HREG_e>(index));
  if (it != registers_.end()) {
    *pRetVal = it->second;
    return S_OK;
  }

  // Even though this isn't in the function's contract, this ensures we'll pick
  // up on unexpected register retrieval attempts.
  // TODO(manzagop): add symbolic names for the registers.
  LOG(ERROR) << base::StringPrintf("Failed to get register value (%u).", index);
  DCHECK(false);
  return E_FAIL;
}

STDMETHODIMP StackWalkHelper::put_registerValue(DWORD index, ULONGLONG NewVal) {
  registers_[static_cast<CV_HREG_e>(index)] = NewVal;
  return S_OK;
}

STDMETHODIMP StackWalkHelper::readMemory(MemoryTypeEnum unused_type,
                                         ULONGLONG va,
                                         DWORD cbData,
                                         DWORD* pcbData,
                                         BYTE* pbData) {
  DCHECK(pcbData != NULL);

  // Handle the 0 size case.
  if (cbData == 0) {
    *pcbData = 0;
    return S_OK;
  }

  // Ensure range validity.
  AddressRange range(va, cbData);
  if (!range.IsValid()) {
    LOG(ERROR) << "Invalid memory range.";
    return E_FAIL;
  }

  // Read from the backing process state.
  size_t bytes_read = 0U;
  if (process_state_->GetFrom(range, &bytes_read, pbData)) {
    // Note: this may only be a partial read.
    *pcbData = bytes_read;
    return S_OK;
  }

  // If the memory comes from a module's range, attempt to service from the
  // module.
  // TODO(manzagop): success should depend on whether the module's memory mathes
  // the requested memory type.
  bytes_read = 0U;
  if (ReadFromModule(range, &bytes_read, pbData)) {
    LOG(INFO) << "Servicing read from module. May not reflect actual memory.";
    *pcbData = bytes_read;
    return S_OK;
  }

  // TODO(manzagop): introduce a function for logging VA to avoid crashing on
  // unexercised code when the error case occurs.
  LOG(ERROR) << base::StringPrintf("\n Read failed (va: %08llx, size: %04x)",
                                   va, cbData);
  return E_FAIL;
}

STDMETHODIMP StackWalkHelper::searchForReturnAddress(IDiaFrameData* frame,
                                                     ULONGLONG* returnAddress) {
  return E_NOTIMPL;  // Use DIA's default search.
}

STDMETHODIMP StackWalkHelper::searchForReturnAddressStart(
    IDiaFrameData* frame,
    ULONGLONG startAddress,
    ULONGLONG* returnAddress) {
  return E_NOTIMPL;  // Use DIA's default search.
}

STDMETHODIMP StackWalkHelper::frameForVA(ULONGLONG va,
                                         IDiaFrameData** frame_data) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSessionByVa(va, session.Receive())) {
    LOG(ERROR) << "Failed to get dia session by va.";
    return E_FAIL;
  }

  // Get the table that is a frame data enumerator.
  base::win::ScopedComPtr<IDiaEnumFrameData> frame_enumerator;
  pe::SearchResult result =
      pe::FindDiaTable(__uuidof(IDiaEnumFrameData), session.get(),
                       frame_enumerator.ReceiveVoid());
  if (result != pe::kSearchSucceeded) {
    LOG(ERROR) << "Failed to obtain frame data from the pdb.";
    return E_FAIL;
  }

  // Get the frame data.
  HRESULT hr = frame_enumerator->frameByVA(va, frame_data);
  if (hr != S_OK) {
    if (hr == S_FALSE) {
      LOG(ERROR) << "No frame data matches specified address.";
    } else {
      LOG(ERROR) << "Failed to get frame data.";
    }
  }

  return hr;
}

STDMETHODIMP StackWalkHelper::symbolForVA(ULONGLONG va, IDiaSymbol** ppSymbol) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSessionByVa(va, session.Receive())) {
    LOG(ERROR) << "Failed to get dia session by va.";
    return E_FAIL;
  }

  // Search for a function.
  base::win::ScopedComPtr<IDiaSymbol> function;
  HRESULT hr = session->findSymbolByVA(va, SymTagFunction, function.Receive());
  if (hr == S_OK) {
    // Get the associated function type.
    base::win::ScopedComPtr<IDiaSymbol> function_type;
    if (function->get_type(function_type.Receive()) != S_OK) {
      LOG(ERROR) << "Failed to get function's type.";
      return E_FAIL;
    }
    DWORD symtag = 0U;
    DCHECK_EQ(S_OK, function_type->get_symTag(&symtag));
    DCHECK(symtag == SymTagFunctionType);

    *ppSymbol = function_type.Detach();
  } else {
    // Note: not having symbols is to be expected sometimes.
    LOG(INFO) << base::StringPrintf("No symbols for VA (%08llx).", va);
  }

  return hr;
}

STDMETHODIMP StackWalkHelper::pdataForVA(ULONGLONG va,
                                         DWORD cbData,
                                         DWORD* pcbData,
                                         BYTE* pbData) {
  // TODO(manzagop): implement to handle 64 bit stack walking.
  return E_NOTIMPL;
}

STDMETHODIMP StackWalkHelper::imageForVA(ULONGLONG vaContext,
                                         ULONGLONG* pvaImageStart) {
  // Get module's base address.
  // TODO(manzagop): set up indexing to optimize this.
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(vaContext, &module_record)) {
    LOG(ERROR) << "Failed to find module for VA.";
    return E_FAIL;
  }
  *pvaImageStart = module_record->range().start();
  return S_OK;
}

STDMETHODIMP StackWalkHelper::addressForVA(ULONGLONG va,
                                           _Out_ DWORD* pISect,
                                           _Out_ DWORD* pOffset) {
  base::win::ScopedComPtr<IDiaSession> session;
  if (!GetDiaSessionByVa(va, session.Receive())) {
    LOG(ERROR) << "Failed to get dia session by va.";
    return E_FAIL;
  }

  HRESULT hr = session->addressForVA(va, pISect, pOffset);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get address for va.";
  }

  return hr;
}

bool StackWalkHelper::ReadFromModule(const AddressRange& range,
                                     size_t* bytes_read,
                                     void* buffer) {
  DCHECK(bytes_read);
  *bytes_read = 0U;

  // Identify the module
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(range.start(), &module_record))
    return false;

  // TODO(manzagop): actually implement the read instead of successfully
  // reading 0 bytes.

  return true;
}

bool StackWalkHelper::EnsurePdbSessionCached(
    const pe::PEFile::Signature& signature,
    std::wstring* cache_key) {
  // Determine the cache key. Note that the cache key does not contain the
  // module's base address.
  base::SStringPrintf(cache_key, L"%ls:%d:%d:%d", signature.path,
                      signature.module_size, signature.module_checksum,
                      signature.module_time_date_stamp);
  auto session_it = pdb_sessions_.find(*cache_key);
  if (session_it != pdb_sessions_.end())
    return true;  // A session (or lack thereof) is cached.

  // The module is not in the cache. Attempt to create a dia session for the
  // module.

  // Create negative cache entries, which will be replaced on success.
  pdb_sources_[*cache_key] = base::win::ScopedComPtr<IDiaDataSource>();
  pdb_sessions_[*cache_key] = base::win::ScopedComPtr<IDiaSession>();

  base::FilePath pdb_path;
  if (!GetPdbPath(signature, &pdb_path))
    return false;

  // Get a source for the pdb.
  base::win::ScopedComPtr<IDiaDataSource> pdb_source;
  HRESULT hr = pdb_source.CreateInstance(CLSID_DiaSource);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to create DIA source: " << common::LogHr(hr);
    return false;
  }
  hr = pdb_source->loadDataFromPdb(pdb_path.value().c_str());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to load PDB: " << common::LogHr(hr);
    return false;
  }

  // Get the session.
  base::win::ScopedComPtr<IDiaSession> pdb_session;
  hr = pdb_source->openSession(pdb_session.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to open session: " << common::LogHr(hr);
    return false;
  }

  // Cache source and session.
  pdb_sources_[*cache_key] = pdb_source;
  pdb_sessions_[*cache_key] = pdb_session;

  return true;
}

bool StackWalkHelper::GetDiaSessionByVa(ULONGLONG va,
                                        IDiaSession** retrieved_session) {
  DCHECK(retrieved_session != NULL);
  *retrieved_session = NULL;

  // Get the module's signature.
  ModuleRecordPtr module_record;
  if (!process_state_->FindSingleRecord(va, &module_record))
    return false;
  scoped_ptr<pe::PEFile::Signature> signature;
  if (!GetModuleSignature(module_record, &signature))
    return false;

  // Retrieve the session.
  std::wstring cache_key;
  if (!EnsurePdbSessionCached(*signature, &cache_key))
    return false;

  auto session_it = pdb_sessions_.find(cache_key);
  DCHECK(session_it != pdb_sessions_.end());
  base::win::ScopedComPtr<IDiaSession> session = session_it->second;

  if (!session.get())
    return false;  // Negative cache entry.

  *retrieved_session = session.get();
  (*retrieved_session)->AddRef();

  // Set the load address (the same module might be loaded at multiple VAs).
  HRESULT hr = session->put_loadAddress(signature->base_address.value());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to set session's load address: " << common::LogHr(hr);
    return false;
  }

  return true;
}

}  // namespace refinery
