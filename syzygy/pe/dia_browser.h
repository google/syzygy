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
//
// The DiaBrowser browses a Debug Interface Access (DIA) data source according
// to a set of registered patterns of interest, returning the encountered
// symbols to the provided callback. Patterns are constructed using the
// PatternBuilder class, which themselves are built using the factory functions
// in the 'builder' namespace.
//
// For more information on DIA, refer to the MSDN documentation:
// http://msdn.microsoft.com/en-us/library/x93ctkx8(v=vs.80).aspx
//
// TODO(chrisha): If needed, we could allow the assignment of a pattern to a
//    class, and use 'single visit per class' semantics. In the absence of
//    a class, each pattern would be given its own class.

#ifndef SYZYGY_PE_DIA_BROWSER_H_
#define SYZYGY_PE_DIA_BROWSER_H_

#include <dia2.h>
#include <limits.h>
#include <windows.h>
#include <bitset>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/callback.h"
#include "base/win/scoped_comptr.h"

namespace pe {

// We declare a few constants to make it easy to iterate through the SymTagEnum
// (declared in cvconst.h).
enum SymTagConstants {
  kSymTagBegin = SymTagExe,
  kSymTagEnd = SymTagMax,
  kSymTagCount = kSymTagEnd - kSymTagBegin
};

typedef enum SymTagEnum SymTag;
typedef std::bitset<kSymTagCount> SymTagBitSet;

extern const SymTag kSymTagInvalid;

namespace builder {
class Proxy;
}  // namespace builder

// The DiaBrowser browses a DIA data source; see the comment at the top of this
// header file for more detail.
class DiaBrowser {
 public:
  typedef base::win::ScopedComPtr<IDiaSymbol> SymbolPtr;
  typedef std::vector<SymbolPtr> SymbolPtrVector;
  typedef std::vector<SymTag> SymTagVector;

  // Used by the callback to provide feedback regarding how the search should
  // proceed from the point of a partial match checkpoint, or a full match.
  enum BrowserDirective {
    // Continue browsing as per normal.
    kBrowserContinue,

    // Stop browsing on this particular search path for this pattern.
    kBrowserTerminatePath,

    // Stop browsing for any further matches to this pattern.
    kBrowserTerminatePattern,

    // Stop the browser entirely.
    kBrowserTerminateAll,

    // Stop the browser and return in error.
    kBrowserAbort
  };

  // The match callback is invoked for each symbol on a matched pattern element
  // that has a callback. The callback receives the following parameters:
  //   1. const DiaBrowser& dia_browser the invoking DiaBrowser
  //   2. const SymTagVector& tag_lineage the stack of matched tags.
  //   3. const SymbolPtrVector& symbol_lineage the stack of matched symbols.
  // It returns a BrowserDirective, telling DiaBrowser how to proceed.
  typedef base::Callback<BrowserDirective(
      const DiaBrowser&,
      const SymTagVector&,
      const SymbolPtrVector&)> MatchCallback;

  // The basic element of a pattern.
  struct PatternElement;

  // Acts as a lightweight interface for building patterns.
  // Patterns are regex-like constructions that attempt to match paths in
  // a tree of IDiaSymbols.
  class PatternBuilder;

  ~DiaBrowser();

  // Adds a pattern to the DiaBrowser. Returns false if the given pattern
  // can't be added. Currently, this will only occur if the given pattern
  // allows a null match. More precisely, a pattern will match null if the
  // root node of the pattern is an exit node of the entire pattern. Such
  // patterns are strictly forbidden. An example of such a pattern:
  //
  //   Opt(SymTagCompiland)
  //
  // Similarly, any pattern that can never match will be ignored. An example
  // of such a pattern is: Not(SymTagNull).
  //
  // For full details on how to construct patterns, see the comment preceding
  // the 'builder' namespace.
  // @param pattern_builder_proxy The pattern to register, built by an
  //     instance of builder::Proxy.
  // @param push_callback The callback that will be invoked when the symbol is
  //     matched and initially visited.
  // @param pop_callback If provided this callback will be invoked when the
  //     matched element is popped off the stack of matches as the browser
  //     retreats up the stack in its depth-first search. Allows clients to
  //     maintain a shadow stack with metadata.
  bool AddPattern(const builder::Proxy& pattern_builder_proxy,
                  const MatchCallback& push_callback);
  bool AddPattern(const builder::Proxy& pattern_builder_proxy,
                  const MatchCallback& push_callback,
                  const MatchCallback& pop_callback);

  // Browses through the DIA tree starting from the given root,
  // matching existing patterns and calling their callbacks.
  // Returns true when the browse terminates naturally, false if any errors
  // were encountered. You can not call Browse twice simultaneously on the
  // same DiaBrowser! (In other words, don't call it again from within a
  // callback.)
  bool Browse(IDiaSymbol* root);

 protected:
  // The following protected functions are intended for use by the GTest
  // fixture only.

  // Tests a vector of SymTags to see if they would match a given pattern.
  // Returns the number of ways this sequence matched any of the patterns.
  size_t TestMatch(const SymTagVector& sym_tags) const;

 private:
  // This initializes the search front and other bookkeeping structures.
  void PrepareForBrowse();

  // Cleans up our various bookkeeping data structures. After calling this
  // the DiaBrowser can be reused.
  void Reset();

  // This advances our search front by trying to advance the symbol with
  // @p sym_tag and @p symbol_id along all possible paths. Any associated
  // callbacks will also be invoked and their directives handled. It also
  // populates sym_tags with the set of tags that will match at the next level
  // of recursion in the search.
  // This can return a reduced subset of BrowserDirective, namely:
  // kBrowserContinue, kBrowserTerminatePath, kBrowserTerminateAll,
  // or kBrowserAbort.
  BrowserDirective PushMatch(SymTag sym_tag,
                             uint32_t symbol_id,
                             SymTagBitSet* sym_tags);

  // This rolls back our search stack by one level, calling pop callbacks.
  DiaBrowser::BrowserDirective PopMatch(bool do_callbacks);

  // The actual implementation of Browse, modulo some startup stuff.
  // This can return a reduced subset of BrowserDirective, namely:
  // kBrowserContinue, kBrowserTerminateAll, or kBrowserAbort.
  BrowserDirective BrowseImpl(IDiaSymbol* root, size_t depth);

  // This iterates all symbols with symbol tag @p sym_tag that are immediate
  // descendants of @p root.
  // This can return a reduced subset of BrowserDirective, namely:
  // kBrowserContinue, kBrowserTerminateAll, or kBrowserAbort.
  BrowserDirective BrowseEnum(IDiaSymbol* root, size_t depth, SymTag sym_tag);

  // The set of visited nodes. The first parameter is the address of the
  // element that matched, the second is the actual ID of the visited node.
  // The PDB has cyclic connections, so we must use some form of limiting to
  // ensure that cycles get broken. However, we want the symbol to be reachable
  // via each matching pattern and not just via the first one walked.
  // TODO(chrisha): Use a hash_map here instead, to minimize allocations?
  std::set<std::pair<const PatternElement*, uint32_t> > visited_;

  // The search patterns we're using. All patterns stored here must be valid.
  // We manually manage memory because we require a 'delete []' to be called
  // on each pattern, something which scoped_array does not do. Similarly,
  // std::unique_ptr is unsuitable for use in a std::vector.
  std::vector<PatternElement*> patterns_;

  // Stores the path of matched symbol tags.
  SymTagVector tag_lineage_;
  // Stores the path of matched symbols.
  SymbolPtrVector symbol_lineage_;

  // The front of our advancing search. This stores those PatternElements that
  // are active.
  std::vector<PatternElement*> front_;

  // This stores the size of the front at the given search stack depth. During
  // the search this will never be empty.
  std::vector<size_t> front_size_;

  // This indicates which of the search patterns have been stopped.
  std::vector<bool> stopped_;

  // A stack of SymTagBitSet objects used for guiding the search at each
  // level of recursion. We use a single vector of these to minimize
  // reallocation at every call to BrowseImpl.
  std::vector<SymTagBitSet> sym_tags_;
};

// The builder namespace contains the factory functions that are used to create
// search patterns. They are in their own namespace so as not to pollute the
// base namespace with their short and potentially common functions names, but
// also so that they can be more easily used with 'using builder' or
// 'using builder::<function name>' declarations.
namespace builder {

typedef DiaBrowser::PatternBuilder PatternBuilder;
typedef DiaBrowser::MatchCallback MatchCallback;

// A lightweight proxy class for inputting arguments to the PatternBuilder
// factories. This proxy allows us to hide the PatternBuilder declaration in
// the .cc file.
class Proxy {
 public:
  Proxy();
  explicit Proxy(const PatternBuilder& proxy);

  // These are left implicit so that SymTags and SymTagBitSets can be used
  // natively in the 'builder' factories.
  Proxy(SymTag sym_tag);  // NOLINT
  Proxy(SymTagBitSet sym_tags);  // NOLINT

  ~Proxy();

  // Dereferencing and casting operators that give access to the underlying
  // PatternBuilder object.
  const PatternBuilder* operator->() const { return pattern_builder_; }
  operator const PatternBuilder*() const { return pattern_builder_; }
  const PatternBuilder& operator*() const { return *pattern_builder_; }
  operator const PatternBuilder&() const { return *pattern_builder_; }

 private:
  PatternBuilder* pattern_builder_;
};

// The functions in this namespace act as factories for PatternBuilders.
// Each DIA symbol has associated with it a path of symbol tags. For a full list
// of DIA symbols, refer to cvconst.h or the MSDN documentation here:
// http://msdn.microsoft.com/en-us/library/bkedss5f(v=vs.80).aspx
//
// By convention we represent a path of symbol tags in the following manner:
//
//   Compiland.Function.Block.Block.Data
//
// PatternBuilder is used to build regex-like expressions over these paths,
// where each tag is treated somewhat like a letter in a standard string
// regex. For example, the following pattern would exactly match the example
// path, and only the example path:
//
//   Seq(Compiland, Function, Block, Block, Data)
//
// Suppose we also wanted to match
//
//   Compiland.Function.Block.Data, and
//   Compiland.Function.Data
//
// To do so, we wish to make the Block tag free to be matched zero or more
// times, accomplished by the following pattern:
//
//   Seq(Compiland, Function, Star(Block), Data)
//
// The patterns created by the pattern builder have an implicit '^' anchor
// at the beginning, forcing them to match from the beginning of the symbol
// path. In all other senses, they behave identically to their standard regex
// counterparts.
//
// We specifically disallow any pattern that would cause a successful match
// of the null string. For example, all of the following patterns would
// successfully match the null string:
//
//   Opt(Compiland)
//   Or(Opt(Compiland),Opt(Data))
//   Opt(Or(Compiland, Data))
//   Star(Data)
//
// Such patterns can be created, but will fail to be inserted into a
// DiaBrowser instance.
//
// In order to maintain consistency with IDiaSymbol::findChildren, we treat
// the special value SymTagNull as a wild-card, matching any of the other
// SymTagEnum values. See MSDN documentation for more info:
// http://msdn.microsoft.com/en-us/library/yfx1573w(v=vs.80).aspx

// Represents a pattern that matches a single SymTag. Equivalent to
// regex /a/.
Proxy Tag(SymTag sym_tag);

// Represents a pattern that matches a set of SymTags represented by
// a SymTagBitSet. Equivalent to regex /(a|b|c)/.
Proxy Tags(SymTagBitSet sym_tags);

// Represents a pattern that matches at least two tags. Equivalent to
// regex /(a|b|c)/.
Proxy Tags(SymTag st0, SymTag st1,
           SymTag st2 = kSymTagInvalid, SymTag st3 = kSymTagInvalid,
           SymTag st4 = kSymTagInvalid, SymTag st5 = kSymTagInvalid,
           SymTag st6 = kSymTagInvalid, SymTag st7 = kSymTagInvalid);

// Represents a pattern that matches all but the SymTags represented
// by the given SymTagBitSet. Equivalent to regex pattern /[^abc]/.
Proxy Not(SymTagBitSet sym_tags);

// Represents a pattern that matches all but the indicated SymTags.
// Equivalent to regex pattern /[^abc]/. Careful, doing Not(SymTagNull)
// will allow you to build an empty SymTagSet which will match nothing.
// This will fail on AddPattern, however.
Proxy Not(SymTag st0,
          SymTag st1 = kSymTagInvalid,
          SymTag st2 = kSymTagInvalid, SymTag st3 = kSymTagInvalid,
          SymTag st4 = kSymTagInvalid, SymTag st5 = kSymTagInvalid,
          SymTag st6 = kSymTagInvalid, SymTag st7 = kSymTagInvalid);

// Represents a pattern that matches the given sub-patterns in order.
// Equivalent to regex /abc/.
Proxy Seq(const Proxy& p0, const Proxy& p1,
          const Proxy& p2 = Proxy(), const Proxy& p3 = Proxy(),
          const Proxy& p4 = Proxy(), const Proxy& p5 = Proxy(),
          const Proxy& p6 = Proxy(), const Proxy& p7 = Proxy());

// Represents a pattern that matches exactly one of the given sub-patterns.
// Equivalent to regex /(a|b|c)/.
Proxy Or(const Proxy& p0, const Proxy& p1,
         const Proxy& p2 = Proxy(), const Proxy& p3 = Proxy(),
         const Proxy& p4 = Proxy(), const Proxy& p5 = Proxy(),
         const Proxy& p6 = Proxy(), const Proxy& p7 = Proxy());

// Represents a pattern that may or may not match the given sub-pattern.
// Equivalent to regex /a?/.
Proxy Opt(const Proxy& p);

// Represents a pattern that may be matched one or more times.
// Equivalent to regex /a+/.
Proxy Plus(const Proxy& p);

// Represents a pattern that may be matched zero or more times.
// Equivalent to regex /a*/.
Proxy Star(const Proxy& p);

// Represents a pattern which, when fully matched, will invoke the given
// @p callback. This callback can direct the behaviour of the match,
// causing it to terminate early. See BrowserDirective for more details.
// If two callbacks are provided the first is called when the pattern is
// matched and the second is called when the matching element is popped off
// the symbol stack as the DFS retreats.
Proxy Callback(const Proxy& p, const MatchCallback& push_callback);
Proxy Callback(const Proxy& p,
               const MatchCallback& push_callback,
               const MatchCallback& pop_callback);


}  // namespace builder

}  // namespace pe

#endif  // SYZYGY_PE_DIA_BROWSER_H_
