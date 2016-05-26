// Copyright 2016 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_AGENT_ASAN_REPORTERS_EXPORTED_FUNCTION_H_
#define SYZYGY_AGENT_ASAN_REPORTERS_EXPORTED_FUNCTION_H_

#include "base/callback.h"
#include "base/logging.h"

namespace agent {
namespace asan {
namespace reporters {

// A templated class representing an exported funtion with a given name and
// signature. The instantiator must defined the static |name_| variable.
// Instances of these are used for injecting callbacks to be used instead of
// exported functions, allowing testing of a reporter that depends on exported
// functions. See ExportedFunction<> below for instantiation details.
//
// There might be multiple export functions with the same signature, but
// different names. In this case the user should provide a distinct ID for the
// type definition to ensure they don't collide.
//
// @tparam I The unique integer ID of the function.
// @tparam F The function type.
// @tparam R The function return type.
// @tparam A The function argument types.
template<int I, typename F, typename R, typename... A>
class ExportedFunctionImpl {
 public:
  using Type = F*;
  using CallbackType = base::Callback<F>;

  ExportedFunctionImpl() : function_(nullptr) {}

  // Constructor with an explicit function pointer.
  explicit ExportedFunctionImpl(Type* function)
      : function_(function) {
  }

  // Constructor with an explicit callback.
  explicit ExportedFunctionImpl(const CallbackType& callback)
      : callback_(callback) {
  }

  // Implicit copy constructor.
  ExportedFunctionImpl(const ExportedFunctionImpl& rhs)  // NOLINT
      : function_(rhs.function_), callback_(rhs.callback_) {
  }

  // Assignment operator.
  ExportedFunctionImpl& operator=(const ExportedFunctionImpl& rhs) {
    function_ = rhs.function_;
    callback_ = rhs.callback_;
    return *this;
  }

  // @returns the name of the export.
  static const char* name() { return name_; }

  // Looks up the export, sets the function pointer and clears any callback.
  // @returns true if the export was found, false otherwise.
  bool Lookup() {
    callback_.Reset();
    HMODULE exe_hmodule = ::GetModuleHandle(NULL);
    function_ = reinterpret_cast<Type>(
        ::GetProcAddress(exe_hmodule, name()));
    return function_ != nullptr;
  }

  // Explicitly sets the function. Clears the callback.
  // @param function The function pointer to be set.
  void set_function(Type function) {
    callback_.Reset();
    function_ = function;
  }

  // Explicitly sets the callback. Clears the function pointer.
  // @param callback The callback to be set.
  void set_callback(const CallbackType& callback) {
    function_ = nullptr;
    callback_ = callback;
  }

  // Clears this function.
  void Reset() {
    function_ = nullptr;
    callback_.Reset();
  }

  bool IsValid() const {
    return function_ != nullptr || !callback_.is_null();
  }

  // Invokes the configured function or callback.
  R Run(A... args) {
    DCHECK(IsValid());
    if (function_ != nullptr)
      return (*function_)(args...);
    return callback_.Run(args...);
  }

  // Accessor for the underlying function.
  Type function() const { return function_; }
  CallbackType callback() const { return callback_; }

 private:
  // The name of the export.
  static const char* name_;

  // The function itself.
  Type function_;

  // An equivalent callback.
  CallbackType callback_;
};

// Template magic for cleaner instantiation of ExportedFunction.
template<typename FunctionType, int TypeId = 0> class ExportedFunction;
template<typename R, typename... A>
class ExportedFunction<R __cdecl(A...), 0> : public ExportedFunctionImpl<
    0, R __cdecl(A...), R, A...> {};
template<int I, typename R, typename... A>
class ExportedFunction<R __cdecl(A...), I> : public ExportedFunctionImpl<
    I, R __cdecl(A...), R, A...> {};

}  // namespace reporters
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_REPORTERS_EXPORTED_FUNCTION_H_
