// Copyright 2012 Google Inc.
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
// Symbol lookup service implementation.
#ifndef SAWBUCK_LOG_LIB_SYMBOL_LOOKUP_SERVICE_H_
#define SAWBUCK_LOG_LIB_SYMBOL_LOOKUP_SERVICE_H_

#include <string>
#include <vector>
#include "base/callback.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"
#include "sawbuck/sym_util/module_cache.h"
#include "sawbuck/sym_util/symbol_cache.h"

class ISymbolLookupService {
 public:
  // Cancellation handle type for an async symbol resolution.
  typedef int Handle;
  static const Handle kInvalidHandle = -1;

  // Type of the resolution callback.
  typedef base::Callback<void(sym_util::ProcessId,
                              base::Time,
                              sym_util::Address,
                              Handle,
                              const sym_util::Symbol&)>
      SymbolResolvedCallback;

  // Enqueues an address resolution request for @p address in the context of
  // @p process_id at @p time.
  // @param process_id the process where @address was observed.
  // @param time the time when @p address was observed.
  // @param address the address to lookup.
  // @param callback a callback object which gets invoked when resolution
  //    completes.
  // @returns the request handle on success, or kInvalidHandle on error.
  virtual Handle ResolveAddress(sym_util::ProcessId process_id,
                                const base::Time& time,
                                sym_util::Address address,
                                const SymbolResolvedCallback& callback) = 0;

  // Cancel a pending async symbol resolution request.
  // @param request_handle a request handle previously returned from
  //    ResolveAddress, whose callback has not yet been invoked.
  virtual void CancelRequest(Handle request_handle) = 0;

  // Change the symbol path to @p symbol_path.
  virtual void SetSymbolPath(const wchar_t* symbol_path) = 0;
};

// Fwd.
namespace base { class MessageLoop; }

// The symbol lookup service class knows how to sink the NT kernel log's
// module events, and to subsequently service {pid,time,address}->symbol
// queries on the processes it's heard of.
class SymbolLookupService
    : public ISymbolLookupService,
      public KernelModuleEvents {
 public:
  SymbolLookupService();
  ~SymbolLookupService();

  typedef base::Callback<void(const wchar_t*)> StatusCallback;
  void set_status_callback(const StatusCallback& status_callback) {
    status_callback_ = status_callback;
  }

  // Accessors for our background thread message loop.
  // Note: This object must outlive the background thread.
  base::MessageLoop* background_thread() const { return background_thread_; }
  void set_background_thread(base::MessageLoop* background_thread) {
    background_thread_ = background_thread;
  }

  // ISymboLookupService implementation.
  virtual Handle ResolveAddress(sym_util::ProcessId process_id,
                                const base::Time& time,
                                sym_util::Address address,
                                const SymbolResolvedCallback& callback);
  virtual void CancelRequest(Handle request_handle);
  virtual void SetSymbolPath(const wchar_t* symbol_path);

  // KernelModuleEvents implementation.
  virtual void OnModuleIsLoaded(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info);
  virtual void OnModuleUnload(DWORD process_id,
                              const base::Time& time,
                              const ModuleInformation& module_info);
  virtual void OnModuleLoad(DWORD process_id,
                            const base::Time& time,
                            const ModuleInformation& module_info);

 private:
  virtual bool ResolveAddressImpl(sym_util::ProcessId process_id,
                                  const base::Time& time,
                                  sym_util::Address address,
                                  sym_util::Symbol* symbol);

  void SetSymbolPathCallback(const std::wstring& path);
  void ResolveCallback();
  void IssueCallbacks();

  base::Lock module_lock_;
  sym_util::ModuleCache module_cache_;  // Under module_lock_.

  // We keep a cache of symbol cache instances keyed on module
  // load state id with an lru replacement policy.
  typedef std::map<sym_util::ModuleCache::ModuleLoadStateId,
      sym_util::SymbolCache> SymbolCacheMap;
  static const size_t kMaxCacheSize = 10;
  typedef std::vector<sym_util::ModuleCache::ModuleLoadStateId>
      LoadStateVector;
  LoadStateVector lru_module_id_;
  SymbolCacheMap symbol_caches_;
  std::wstring symbol_path_;

  base::Lock resolution_lock_;
  struct Request {
    sym_util::ProcessId process_id_;
    base::Time time_;
    sym_util::Address address_;
    SymbolResolvedCallback callback_;
    sym_util::Symbol resolved_;
  };
  // Under resolution_lock_.
  typedef std::map<Handle, Request> RequestMap;

  // This map contains pending and completed requests.
  RequestMap requests_;
  // Next request id issued.
  Handle next_request_id_;  // Under resolution_lock_.
  // The id of the largest-id unprocessed request.
  Handle unprocessed_id_;  // Under resolution_lock_.

  // Invoked on the worker thread on status changes.
  StatusCallback status_callback_;

  typedef base::Callback<void()> ProcessingCallback;

  // These two store any enqueued or processing task.
  ProcessingCallback resolve_task_;  // Under resolution_lock_.
  ProcessingCallback callback_task_;  // Under resolution_lock_.

  // The background thread where we do our processing.
  base::MessageLoop* background_thread_;

  // The foreground thread where we deliver result callbacks.
  base::MessageLoop* foreground_thread_;
};

#endif  // SAWBUCK_LOG_LIB_SYMBOL_LOOKUP_SERVICE_H_
