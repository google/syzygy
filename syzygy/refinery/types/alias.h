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
// Declares code to defeat the optimizing out variables. This is used instead of
// base::Alias to avoid symbol clutter.

#ifndef SYZYGY_REFINERY_TYPES_ALIAS_H_
#define SYZYGY_REFINERY_TYPES_ALIAS_H_

namespace testing {

void Alias(const void* data_to_alias);

}  // namespace testing

#endif  // SYZYGY_REFINERY_TYPES_ALIAS_H_
