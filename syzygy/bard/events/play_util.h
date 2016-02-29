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
//
// Utility functions for invoking a function with a unique stack. This is
// used during playback of memory profiler traces to ensure that the number
// of unique stack traces is roughly the same.

#ifndef SYZYGY_BARD_EVENTS_PLAY_UTIL_H_
#define SYZYGY_BARD_EVENTS_PLAY_UTIL_H_

#include "syzygy/bard/events/play_util_impl.h"

namespace bard {

// Function for invoking a function with a given set of parameters, ensuring
// that the stack-trace leading to the call is unique for a given stack_id.
// @tparam FunctionType The type of the function to be called.
// @tparam ParamTypes The types of the function parameters.
// @param stack_id The ID of the stack trace to generate.
// @param function A reference to the function to be invoked.
// @param param The parameters to be passed to the function.
template <typename FunctionType, typename... ParamTypes>
typename detail::GetReturnType<FunctionType, ParamTypes...>::type
InvokeFunctionWithStackId(uint32_t stack_id,
                          const FunctionType& function,
                          ParamTypes... params) {
  // Delegate to InvokeFunctionWithStackIdHelper with a depth of 8. This
  // function will take a different path based on each nibble of the stack ID
  // before calling the wrapped function.
  using ReturnType = detail::GetReturnType<FunctionType, ParamTypes...>::type;
  return detail::InvokeFunctionWithStackIdHelper<
      0, FunctionType, ReturnType, ParamTypes...>().Do(
          8, stack_id, function, params...);
}

// Wrapper around InvokeOnFunctionWithStackId which invokes a member function
// on the provided backdrop and provides timing information, collected at the
// leaf.
// @tparam BackdropType The type of the backdrop.
// @tparam ReturnType The return type of the member function.
// @tparam ParamTypes The types of the member function parameters.
// @param stack_id The ID of the stack trace to generate.
// @param timing A pointer to the variable to be populated with the timing
//     results.
// @param backdrop The backdrop on which the member function will be invoked.
// @param function A pointer to the member function to be invoked.
// @param param The parameters to be passed to the function.
template <typename BackdropType, typename ReturnType, typename... ParamTypes>
ReturnType InvokeOnBackdrop(
    uint32_t stack_id,
    uint64_t* timing,
    BackdropType* backdrop,
    ReturnType (BackdropType::*function)(ParamTypes...),
    ParamTypes... params) {
  return detail::InvokeOnBackdropHelper<
      BackdropType, ReturnType, ParamTypes...>::Do(
          stack_id, timing, backdrop, function, params...);
}

}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_PLAY_UTIL_H_
