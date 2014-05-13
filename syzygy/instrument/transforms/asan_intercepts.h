// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declares structures encoding the list of functions that SyzyASAN
// instrumentation intercepts as part of its implementation.
//
// How the intercepts are performed depends on whether the image being
// instrumented is a COFF image or a PE image. In PE images there are two
// mechanisms:
//
// (1) Functions that are imported are redirected by adding new imports and
//     rewriting references. This requires the undecorated name of the function
//     as it is exported, as well as the module to which it belongs.
// (2) Functions that are statically linked into the binary are discovered by
//     their undecorated names, filtered by their contents (to ensure that they
//     have the expected calling convention, as optimization sometimes modify
//     this), and finally redirected to instrumented implementation via
//     reference rewriting.
//
// In COFF files redirection is performed via symbol rewriting. Any references
// to a decorated symbol are replaced with references to the decorated name of
// the equivalent instrumented function. Redirection is applied to both the
// original decorated name (for direct references, and subsequently statically
// linked functions), as well as the '__imp_' prefixed decorated name (which
// results in the creation of an import entry in the final linked image).

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTS_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTS_H_

namespace instrument {
namespace transforms {

// A null-terminated hex-encoded MD5 hash, as a string. This is used for
// filtering statically linked functions to be intercepted, ensuring that only
// those with a known implementation (and hence calling convention) are
// intercepted.
struct MD5Hash {
  char hash[33];
};

// Metadata describing a function to be intercepted.
struct AsanIntercept {
  // The undecorated function name. This is required for the PE version of
  // the transform.
  const char* undecorated_name;
  // The fully decorated name of the function. This is required for the COFF
  // version of the transform. If unknown then this may be NULL, in which case
  // this intercept will not be implemented for COFF instrumentation.
  const char* decorated_name;

  // The module the function. This only needs to be specified if the function
  // is possibly included in a PE module as an import. Only referenced by the
  // PE version of the transform. Set to NULL if module information is not
  // necessary.
  const char* module;

  // A NULL terminated array of MD5 hashes of recognized versions of this
  // functions content. This is necessary to ensure that we only intercept
  // unoptimized versions of this function in PE files. This is only used by the
  // PE version of the transform.
  const MD5Hash* valid_content_hashes;

  // If true then intercepting this function is optional, and potentially
  // disabled by the '--no-interceptors' command-line flag.
  bool optional;
};

// List of ASAN intercepts. The terminating entry will contain all NULLs.
// Functions that have the same value for |module| will be consecutive in this
// array.
extern const AsanIntercept kAsanIntercepts[];

// The prefix that is applied to the name of ASAN instrumented implementations
// of intercepted functions.
extern const char kUndecoratedAsanInterceptPrefix[];
extern const char kDecoratedAsanInterceptPrefix[];

// The prefix that is applied to decorated symbol names that represent an
// indirect (via dynamic import) reference to a function. The .lib file
// associated with a DLL takes care of defining these.
extern const char kDecoratedImportPrefix[];

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_INTERCEPTS_H_
