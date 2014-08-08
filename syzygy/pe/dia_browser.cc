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
#include "syzygy/pe/dia_browser.h"

#include "base/logging.h"

namespace {

using pe::SymTag;
using pe::SymTagBitSet;
using pe::kSymTagBegin;
using pe::kSymTagEnd;

// Adds a sym_tag to set of SymTagBitSet. Handles the special case of SymTagNull
// by adding *all* tags.
void AddToSymTagBitSet(SymTag tag, SymTagBitSet* set) {
  if (tag == SymTagNull) {
    set->set();
  } else {
    if (tag < kSymTagBegin || tag >= kSymTagEnd)
      return;
    set->set(static_cast<size_t>(tag) - kSymTagBegin);
  }
}

bool SymTagBitSetContains(SymTagBitSet set, SymTag tag) {
  DCHECK(tag != SymTagNull);
  return set.test(tag - kSymTagBegin);
}

}  // namespace

namespace pe {

using base::win::ScopedComPtr;

const SymTag kSymTagInvalid(static_cast<SymTag>(-1));

// Defines an element in a pattern.
struct DiaBrowser::PatternElement {
  PatternElement()
      : sym_tags(),
        outgoing_sym_tags(),
        links(),
        pattern_id(-1),
        full_match(false) {
  }

  ~PatternElement() {
  }

  // Returns true if @p sym_tag matches the SymTagBitSet represented
  // by this PatternElement.
  bool Matches(SymTag sym_tag) const {
    return SymTagBitSetContains(sym_tags, sym_tag);
  }

  // Invokes the callback on this PatternElement, if present.
  BrowserDirective InvokeCallback(const DiaBrowser& browser,
                                  const SymTagVector& tag_lineage,
                                  const SymbolPtrVector& symbol_lineage,
                                  const MatchCallback& callback) const {
    BrowserDirective directive = kBrowserContinue;
    if (!callback.is_null())
      directive = callback.Run(browser, tag_lineage, symbol_lineage);

    if (directive == kBrowserContinue && links.empty())
      directive = kBrowserTerminatePath;

    return directive;
  }

  BrowserDirective InvokePushCallback(
      const DiaBrowser& browser,
      const SymTagVector& tag_lineage,
      const SymbolPtrVector& symbol_lineage) const {
    return InvokeCallback(browser, tag_lineage, symbol_lineage, push_callback);
  }

  BrowserDirective InvokePopCallback(
      const DiaBrowser& browser,
      const SymTagVector& tag_lineage,
      const SymbolPtrVector& symbol_lineage) const {
    return InvokeCallback(browser, tag_lineage, symbol_lineage, pop_callback);
  }

  // Calculates the outgoing sym_tags for this element.
  void CalculateOutgoingSymtags() {
    outgoing_sym_tags.reset();
    for (size_t i = 0; i < links.size(); ++i)
      outgoing_sym_tags |= links[i]->sym_tags;
  }

  // The set of symbols that may be matched at this node.
  SymTagBitSet sym_tags;

  // The union of all outgoing link SymTagBitSets.
  SymTagBitSet outgoing_sym_tags;

  // These are links to other PatternElements in the same pattern.
  std::vector<PatternElement*> links;

  // This indicates to which pattern this element belongs.
  // TODO(chrisha): Maybe a separate category_id for visited_ bookkeeping?
  size_t pattern_id;

  // If this is non-null, when reaching this point in the pattern we will
  // invoke the callback.
  MatchCallback push_callback;
  // This callback will be invoked when retreating back up the stack of matches.
  MatchCallback pop_callback;

  // If this is true, this node is an exit node for the pattern. Any time
  // we reach this node, a full match has been achieved.
  bool full_match;
};

// The PatternBuilder class represents regex-like patterns over SymTag paths.
class DiaBrowser::PatternBuilder {
 public:
  enum PatternType {
    kPatternNone,
    kPatternTags,
    kPatternSeq,
    kPatternOr,
    kPatternOpt,
    kPatternPlus,
    kPatternStar,
    kPatternCallback
  };

  PatternBuilder()
      : type_(kPatternNone) {
  }

  explicit PatternBuilder(SymTag sym_tag)
      : type_(kPatternTags) {
    DCHECK(sym_tag != kSymTagInvalid);
    AddToSymTagBitSet(sym_tag, &sym_tags_);
    DCHECK(sym_tags_.count() > 0);
  }

  explicit PatternBuilder(SymTagBitSet sym_tags)
      : type_(kPatternTags),
        sym_tags_(sym_tags) {
    // We don't DCHECK(sym_tags_.count() > 0) because it's possible and valid
    // for a SymTagBitSet to be empty. This will fail on AddPattern, however.
  }

  // For constructing kPatternSeq/kPatternOr patterns.
  PatternBuilder(PatternType type,
                 const PatternBuilder& pb0,
                 const PatternBuilder& pb1)
      : type_(type),
        pb0_(new PatternBuilder()),
        pb1_(new PatternBuilder()) {
    DCHECK(type_ == kPatternSeq || type_ == kPatternOr);
    DCHECK(pb0.type_ != kPatternNone && pb1.type_ != kPatternNone);
    pb0_->CopyFrom(pb0);
    pb1_->CopyFrom(pb1);
  }

  // For constructing kPatternOpt/kPatternPlus/kPatternStar patterns.
  PatternBuilder(PatternType type, const PatternBuilder& pb)
      : type_(type),
        pb0_(new PatternBuilder()) {
    DCHECK(type_ == kPatternOpt || type_ == kPatternPlus ||
           type_ == kPatternStar);
    DCHECK(pb.type_ != kPatternNone);
    pb0_->CopyFrom(pb);
  }

  // For constructing kPatternCallback patterns.
  PatternBuilder(const PatternBuilder& pb,
                 MatchCallback push_callback,
                 MatchCallback pop_callback)
      : type_(kPatternCallback),
        push_callback_(push_callback),
        pop_callback_(pop_callback),
        pb0_(new PatternBuilder()),
        pb1_() {
    DCHECK(!push_callback.is_null());
    DCHECK(pb.type_ != kPatternNone);
    pb0_->CopyFrom(pb);
  }

  // Performs a deep-copy of the given pattern builder.
  void CopyFrom(const PatternBuilder& pb) {
    type_ = pb.type_;
    sym_tags_ = pb.sym_tags_;
    push_callback_ = pb.push_callback_;
    pop_callback_ = pb.pop_callback_;

    if (pb.pb0_.get() != NULL) {
      if (pb0_.get() == NULL)
        pb0_.reset(new PatternBuilder());
      pb0_->CopyFrom(*pb.pb0_);
    } else {
      pb0_.reset();
    }

    if (pb.pb1_.get() != NULL) {
      if (pb1_.get() == NULL)
        pb1_.reset(new PatternBuilder());
      pb1_->CopyFrom(*pb.pb1_);
    } else {
      pb1_.reset();
    }
  }

  PatternType type() const { return type_; }

  // A utility function that builds the 'or' pattern of two sub-patterns.
  // Performs optimizations as much as possible (merging SymTag and SymTagSet
  // sub-patterns).
  static void OrBuilder(const PatternBuilder& pb0,
                        const PatternBuilder& pb1,
                        PatternBuilder* pbor) {
    // For simplification, we collect Tag-type sub-expressions. We ensure any
    // Or statement contains at most one tagset, and if so, this tagset is in
    // the first sub-expression. Since patterns are build from the inside out
    // (nested sub-expressions first), this simplification will propogate all
    // of the way through a set of nested Or statements.

    if (pb0.type_ == kPatternTags) {
      // If the two sub-expressions are both SymTagSets, merge them.
      if (pb1.type_ == kPatternTags) {
        pbor->CopyFrom(PatternBuilder(pb0.sym_tags_ | pb1.sym_tags_));
        return;
      }

      // If we have Or(tagset0, Or(tagset1, other)), merge to
      // Or(tagset0|tagset1, other).
      if (pb1.type_ == kPatternOr && pb1.pb0_->type_ == kPatternTags) {
        pbor->CopyFrom(pb1);
        pbor->pb0_->sym_tags_ |= pb0.sym_tags_;
        return;
      }

      pbor->CopyFrom(PatternBuilder(kPatternOr, pb0, pb1));
      return;
    }

    // If the first sub-expression is not a tagset, but the second one is,
    // then swap them and rerun the logic. This will do the simplification
    // above.
    if (pb1.type_ == kPatternTags) {
      DCHECK_NE(kPatternTags, pb0.type_);
      return OrBuilder(pb1, pb0, pbor);
    }

    // At this point, neither of the sub-expression is a simple tagset.
    // Bring nested tagsets to the outermost Or expression, if they exist.
    // If the exist, they will be in the first sub-expression.
    DCHECK_NE(kPatternTags, pb0.type_);
    DCHECK_NE(kPatternTags, pb1.type_);
    if (pb0.type_ == kPatternOr && pb0.pb0_->type_ == kPatternTags) {
      // The second entry should never also be a tagset, as it should have
      // been simplified if this were the case.
      DCHECK_NE(kPatternTags, pb0.pb1_->type_);

      // If both are of type Or(tagset, other), then merge their
      // sym_tags and keep the sym_tags as the outermost entry.
      // That is, Or(Or(tagset0, other0), Or(tagset1, other1)) ->
      //          Or(tagset0|tagset1, Or(other0, other1)).
      if (pb1.type_ == kPatternOr && pb1.pb0_->type_ == kPatternTags) {
        PatternBuilder pbA(pb0.pb0_->sym_tags_ | pb1.pb0_->sym_tags_);
        PatternBuilder pbB(kPatternOr, *pb0.pb1_, *pb1.pb1_);
        pbor->CopyFrom(PatternBuilder(kPatternOr, pbA, pbB));
        return;
      }

      // Keep the sym_tags as the first sub-expression.
      PatternBuilder pb(kPatternOr, *pb0.pb1_, pb1);
      pbor->CopyFrom(PatternBuilder(kPatternOr, *pb0.pb0_, pb));
      return;
    }

    // If the second sub-expression contains a nested tagset, but the first
    // does not, swap their order and rerun the logic. The above logic will
    // do the necessary simplification.
    if (pb1.type_ == kPatternOr && pb1.pb0_->type_ == kPatternTags) {
      DCHECK(pb0.type_ != kPatternOr || pb0.pb0_->type_ != kPatternTags);
      return OrBuilder(pb1, pb0, pbor);
    }

    // If we get here, then neither of the sub-expressions contains a tagset.
    DCHECK(pb0.type_ != kPatternOr || pb0.pb0_->type_ != kPatternTags);
    DCHECK(pb1.type_ != kPatternOr || pb1.pb0_->type_ != kPatternTags);
    pbor->CopyFrom(PatternBuilder(kPatternOr, pb0, pb1));
    return;
  }

 protected:
  friend class DiaBrowser;

  // Returns the length of this pattern.
  size_t Length() const {
    switch (type_) {
      case kPatternNone:
        return 0;

      case kPatternTags:
        return 1;

      case kPatternSeq:
      case kPatternOr:
         return pb0_->Length() + pb1_->Length();

      case kPatternOpt:
      case kPatternPlus:
      case kPatternStar:
      case kPatternCallback:
        return pb0_->Length();

      default:
        NOTREACHED() << "Invalid PatternType.";
        return 0;
    }
  }

  // Appends the entries of this pattern to @p entries.
  void GetEntries(PatternElement* pattern,
                  size_t offset,
                  std::vector<PatternElement*>* entries) const {
    switch (type_) {
      case kPatternNone:
        break;

      case kPatternTags:
        entries->push_back(pattern + offset);
        break;

      case kPatternSeq:
      case kPatternOpt:
      case kPatternPlus:
      case kPatternStar:
      case kPatternCallback:
        pb0_->GetEntries(pattern, offset, entries);
        break;

      case kPatternOr:
        pb0_->GetEntries(pattern, offset, entries);
        pb1_->GetEntries(pattern, offset + pb0_->Length(), entries);
        break;

      default:
        NOTREACHED() << "Invalid PatternType.";
        break;
    }
  }

  // Builds this pattern inside of a Pattern. We are given the set
  // of exit nodes of our predecessor pattern, and need to build a set of exit
  // nodes for our pattern. Exit nodes are appended to @p out_exits.
  // @p pattern is the root element of the pattern into which we are building,
  // and @p offset is the location at which we will insert our pattern.
  void Build(PatternElement* pattern,
             size_t offset,
             const std::vector<PatternElement*>& in_exits,
             std::vector<PatternElement*>* out_exits) const {
    switch (type_) {
      case kPatternNone:
        return;

      case kPatternTags: {
        pattern[offset].sym_tags = sym_tags_;
        for (size_t i = 0; i < in_exits.size(); ++i)
          in_exits[i]->links.push_back(pattern + offset);
        out_exits->push_back(pattern + offset);
        return;
      }

      case kPatternSeq: {
        size_t len0 = pb0_->Length();
        std::vector<PatternElement*> exits0;
        pb0_->Build(pattern, offset, in_exits, &exits0);
        pb1_->Build(pattern, offset + len0, exits0, out_exits);
        return;
      }

      case kPatternOr: {
        size_t len0 = pb0_->Length();
        pb0_->Build(pattern, offset, in_exits, out_exits);
        pb1_->Build(pattern, offset + len0, in_exits, out_exits);
        return;
      }

      case kPatternOpt:
      case kPatternPlus:
      case kPatternStar: {
        // Link in the sub-pattern.
        pb0_->Build(pattern, offset, in_exits, out_exits);

        if (type_ != kPatternOpt) {
          // Hook up the output exits to the entries of the sub-pattern,
          // allowing this sub-pattern to be repeated.
          std::vector<PatternElement*> entries;
          pb0_->GetEntries(pattern, offset, &entries);
          for (size_t i = 0; i < out_exits->size(); ++i)
            for (size_t j = 0; j < entries.size(); ++j)
              (*out_exits)[i]->links.push_back(entries[j]);
        }

        if (type_ != kPatternPlus) {
          // Add the input exits to the output exits, making the sub-pattern
          // optional.
          out_exits->insert(out_exits->end(), in_exits.begin(), in_exits.end());
        }
        return;
      }

      case kPatternCallback: {
        pb0_->Build(pattern, offset, in_exits, out_exits);

        // Label the exit points of the sub-pattern with the provided
        // callback.
        for (size_t i = 0; i < out_exits->size(); ++i) {
          (*out_exits)[i]->push_callback = push_callback_;
          (*out_exits)[i]->pop_callback = pop_callback_;
        }
        return;
      }

      default:
        NOTREACHED() << "Invalid PatternType.";
        return;
    }
  }

 private:
  PatternType type_;
  SymTagBitSet sym_tags_;
  MatchCallback push_callback_;
  MatchCallback pop_callback_;
  scoped_ptr<PatternBuilder> pb0_;
  scoped_ptr<PatternBuilder> pb1_;

  DISALLOW_COPY_AND_ASSIGN(PatternBuilder);
};

DiaBrowser::~DiaBrowser() {
  for (size_t i = 0; i < patterns_.size(); ++i)
    delete [] patterns_[i];
}

bool DiaBrowser::AddPattern(const builder::Proxy& pattern_builder_proxy,
                            const MatchCallback& push_callback) {
  return AddPattern(pattern_builder_proxy, push_callback, MatchCallback());
}

bool DiaBrowser::AddPattern(const builder::Proxy& pattern_builder_proxy,
                            const MatchCallback& push_callback,
                            const MatchCallback& pop_callback) {
  const PatternBuilder& pattern_builder(pattern_builder_proxy);
  size_t pattern_length = pattern_builder.Length();

  // Empty patterns are rejected.
  if (pattern_length == 0)
    return false;

  // Build the pattern in place. We increment pattern_length by 1 so to have
  // room for a special root node at the beginning of the pattern.
  ++pattern_length;
  size_t pattern_id = patterns_.size();
  scoped_ptr<PatternElement[]> pattern(new PatternElement[pattern_length]);
  std::vector<PatternElement*> in_exits(1, pattern.get());
  std::vector<PatternElement*> out_exits;
  pattern_builder.Build(pattern.get(), 1, in_exits, &out_exits);

  // If the root element is one of the out_exits, this pattern will match the
  // 'null' sequence. Reject it!
  for (size_t i = 0; i < out_exits.size(); ++i) {
    if (out_exits[i] == pattern.get()) {
      return false;
    }
  }

  // If the root element points to itself, the pattern can match a 'null'
  // sequence. Reject it!
  for (size_t i = 0; i < pattern[0].links.size(); ++i) {
    if (pattern[0].links[i] == pattern.get()) {
      return false;
    }
  }

  // If any element in the pattern matches *no* sym_tags, the pattern is
  // unmatchable. Reject it!
  for (size_t i = 1; i < pattern_length; ++i) {
    if (pattern[i].sym_tags.none()) {
      return false;
    }
  }

  // Mark the exit nodes as being full match nodes, and set their callbacks.
  for (size_t i = 0; i < out_exits.size(); ++i) {
    out_exits[i]->full_match = true;
    out_exits[i]->push_callback = push_callback;
    out_exits[i]->pop_callback = pop_callback;
  }

  // Label the pattern node with the id of this pattern, and precalculate
  // outgoing sym_tagsets as used by Browse.
  for (size_t i = 0; i < pattern_length; ++i) {
    pattern[i].pattern_id = pattern_id;
    pattern[i].CalculateOutgoingSymtags();
  }

  patterns_.push_back(pattern.release());

  return true;
}

// This is a light-weight clone of Browse, without the actual DIA browsing,
// and without callbacks. It is intended largely to test the pattern-matching
// functionality.
size_t DiaBrowser::TestMatch(const SymTagVector& sym_tags) const {
  size_t match_count = 0;
  for (size_t pat_idx = 0; pat_idx < patterns_.size(); ++pat_idx) {
    std::vector<const PatternElement*> front0(1, patterns_[pat_idx]);
    std::vector<const PatternElement*> front1;

    std::vector<const PatternElement*>* active = &front0;
    std::vector<const PatternElement*>* next = &front1;

    for (size_t sym_tag_idx = 0; sym_tag_idx < sym_tags.size(); ++sym_tag_idx) {
      if (active->empty())
        break;

      SymTag sym_tag = sym_tags[sym_tag_idx];
      for (size_t active_idx = 0; active_idx < active->size(); ++active_idx) {
        const PatternElement* elem = (*active)[active_idx];

        if (elem->links.size() == 0 ||
            !SymTagBitSetContains(elem->outgoing_sym_tags, sym_tag))
          continue;

        for (size_t link_idx = 0; link_idx < elem->links.size(); ++link_idx) {
          const PatternElement* elem_next = elem->links[link_idx];
          if (elem_next->Matches(sym_tag))
            next->push_back(elem_next);
        }
      }

      std::swap(active, next);
      next->clear();
    }

    // If we get here, those active nodes marked 'full_match' count as matches.
    for (size_t i = 0; i < active->size(); ++i) {
      const PatternElement* elem = (*active)[i];
      if (elem->full_match)
        ++match_count;
    }
  }

  return match_count;
}

void DiaBrowser::PrepareForBrowse() {
  Reset();

  // Set all patterns as valid, initialize the search front and set up
  // the first set of sym_tags to search for.
  stopped_.resize(patterns_.size());
  sym_tags_.resize(1);
  sym_tags_[0].reset();
  for (size_t i = 0; i < patterns_.size(); ++i) {
    PatternElement* elem = patterns_[i];
    front_.push_back(elem);
    stopped_[i] = false;
    sym_tags_[0] |= elem->outgoing_sym_tags;
  }
  front_size_.push_back(patterns_.size());
}

void DiaBrowser::Reset() {
  visited_.clear();
  tag_lineage_.clear();
  symbol_lineage_.clear();
  front_.clear();
  front_size_.clear();
  stopped_.clear();
  sym_tags_.clear();
}

DiaBrowser::BrowserDirective DiaBrowser::PushMatch(
    SymTag sym_tag, uint32 symbol_id, SymTagBitSet* sym_tags) {
  DCHECK(sym_tags != NULL);
  DCHECK(!front_size_.empty());

  sym_tags->reset();
  size_t new_front = 0;

  // Examine every node at our current level in the front, and advance those
  // that we can.
  size_t front_end = front_.size();
  size_t front_begin = front_end - front_size_.back();
  for (size_t f = front_begin; f < front_end; ++f) {
    size_t patid = front_[f]->pattern_id;
    if (stopped_[patid])
      continue;

    // Iterate over the possible destinations of this element.
    for (size_t l = 0; l < front_[f]->links.size(); ++l) {
      PatternElement* elem = front_[f]->links[l];

      if (!elem->Matches(sym_tag))
        continue;

      // Each element will only be visited once per pattern element.
      if (!visited_.insert(std::make_pair(elem, symbol_id)).second)
        continue;

      // Invoke the callback for each valid destination, and truncate the
      // search if necessary.
      BrowserDirective directive = elem->InvokePushCallback(*this,
                                                            tag_lineage_,
                                                            symbol_lineage_);

      bool need_pop_callback = false;
      switch (directive) {
        // Normal match. Add the destination to the new search front. We don't
        // need a local pop callback because this node will be added to the
        // search front. The pop callback will be invoked when we backtrack
        // later on.
        case kBrowserContinue:
          *sym_tags |= elem->outgoing_sym_tags;
          ++new_front;
          front_.push_back(elem);
          break;

        // Stop searching on this path: do not add the destination to the
        // search front and carry on as usual.
        case kBrowserTerminatePath:
          need_pop_callback = true;
          break;

        // Stop searching using this pattern: do not add the destination to the
        // search front, and mark the pattern as stopped.
        case kBrowserTerminatePattern:
          stopped_[patid] = true;
          l = front_[f]->links.size();
          need_pop_callback = true;
          break;

        // Both of these cause the search to terminate prematurely so we can
        // return immediately.
        case kBrowserTerminateAll:
        case kBrowserAbort:
          return directive;
      }

      // Sometimes elements are the leaf node in a search, in which case we
      // need to immediately follow the push callback with a pop callback.
      // NOTE: We are currently handling the pop callback in two places: in
      // PopMatch and here. We could move all the handling to PopMatch if we
      // also pushed 'dead' search avenues to the front, but this would require
      // keeping additional state in the search front, or changing the semantics
      // of InvokeCallback and the logic in this routine, BrowseImpl and
      // PopMatch. Handling terminated paths here is far simpler.
      if (need_pop_callback) {
        directive = elem->InvokePopCallback(*this,
                                            tag_lineage_,
                                            symbol_lineage_);
        if (directive == kBrowserTerminateAll || directive == kBrowserAbort)
          return directive;
        if (directive == kBrowserTerminatePattern) {
          stopped_[patid] = true;
          break;  // This breaks out of the for loop.
        }
      }
    }
  }

  front_size_.push_back(new_front);
  return new_front == 0 ? kBrowserTerminatePath : kBrowserContinue;
}

DiaBrowser::BrowserDirective DiaBrowser::PopMatch(bool do_callbacks) {
  if (do_callbacks) {
    // Before popping this bunch of elements from the search front, invoke their
    // callbacks with a 'pop' notification.
    size_t i = front_.size() - front_size_.back();
    for (; i < front_.size(); ++i) {
      // If this pattern is already stopped then we don't call the pop
      // callback.
      size_t patid = front_[i]->pattern_id;
      if (stopped_[patid])
        continue;

      // Call the pop callback.
      BrowserDirective directive =
          front_[i]->InvokePopCallback(*this,
                                       tag_lineage_,
                                       symbol_lineage_);

      switch (directive) {
        // The path can't be stopped during a 'pop' notification, as its already
        // been explored by that point. So TerminatePath is a nop.
        case kBrowserContinue:
        case kBrowserTerminatePath:
          break;

        // Stop searching using this pattern. This will prevent it from being
        // used in further search paths.
        case kBrowserTerminatePattern:
          stopped_[patid] = true;
          break;

        // Both of these cause the search to terminate prematurely.
        case kBrowserTerminateAll:
        case kBrowserAbort:
          return directive;
      }
    }
  }

  // Pop off the match history.
  front_.resize(front_.size() - front_size_.back());
  front_size_.pop_back();

  return kBrowserContinue;
}

bool DiaBrowser::Browse(IDiaSymbol* root) {
  PrepareForBrowse();
  BrowserDirective directive = BrowseImpl(root, 0);
  Reset();
  return directive != kBrowserAbort;
}

DiaBrowser::BrowserDirective DiaBrowser::BrowseImpl(IDiaSymbol* root,
                                                    size_t depth) {
  if (sym_tags_[depth].none())
    return kBrowserContinue;

  // Make sure we have a SymTagBitSet for the next level of recursion.
  if (sym_tags_.size() < depth + 2)
    sym_tags_.resize(depth + 2);

  // If all symbols are accepted, we can use SymTagNull as a wildcard rather
  // than iterating over each individual SymTag.
  if (sym_tags_[depth].count() == sym_tags_[depth].size())
    return BrowseEnum(root, depth, SymTagNull);

  // Iterate through all possible symbol tags that can be matched.
  for (size_t i = 0; i < kSymTagCount; ++i) {
    if (!sym_tags_[depth].test(i))
      continue;
    SymTag sym_tag = static_cast<SymTag>(kSymTagBegin + i);
    BrowserDirective directive = BrowseEnum(root, depth, sym_tag);
    if (directive == kBrowserTerminateAll || directive == kBrowserAbort)
      return directive;
  }

  return kBrowserContinue;
}

DiaBrowser::BrowserDirective DiaBrowser::BrowseEnum(
    IDiaSymbol* root, size_t depth, SymTag sym_tag) {
  // Get the enum for this symbol type
  ScopedComPtr<IDiaEnumSymbols> enum_symbols;
  HRESULT hr = root->findChildren(sym_tag,
                                  NULL,
                                  nsNone,
                                  enum_symbols.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get DIA symbol enumerator: " << hr << ".";
    return kBrowserAbort;
  }

  // Sometimes a NULL enum gets returned rather than an empty
  // enum. (Why?)
  if (enum_symbols.get() == NULL)
    return kBrowserContinue;

  BrowserDirective directive = kBrowserContinue;
  tag_lineage_.push_back(SymTagNull);
  symbol_lineage_.push_back(SymbolPtr());

  // Iterate through the returned symbols.
  while (true) {
    SymbolPtr symbol;
    ULONG fetched = 0;
    hr = enum_symbols->Next(1, symbol.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate DIA symbols: " << hr << ".";
      directive = kBrowserAbort;
      break;
    }
    // No more symbols?
    if (fetched == 0)
      break;

    // Get the symbol ID and tag type.
    DWORD symbol_id = 0;
    DWORD actual_sym_tag_dw = SymTagNull;
    if (FAILED(symbol->get_symIndexId(&symbol_id)) ||
        FAILED(symbol->get_symTag(&actual_sym_tag_dw))) {
      NOTREACHED() << "Failed to get symbol properties.";
      directive = kBrowserAbort;
      break;
    }
    SymTag actual_sym_tag = static_cast<SymTag>(actual_sym_tag_dw);
    if (sym_tag != SymTagNull)
      DCHECK_EQ(sym_tag, actual_sym_tag);

    tag_lineage_.back() = actual_sym_tag;
    symbol_lineage_.back() = symbol;

    // Try to extend the match using this symbol. If this succeeds, recurse.
    directive = PushMatch(actual_sym_tag, symbol_id, &sym_tags_[depth + 1]);
    if (directive == kBrowserContinue)
      directive = BrowseImpl(symbol.get(), depth + 1);
    if (directive == kBrowserTerminateAll || directive == kBrowserAbort) {
      // We've terminated the search already, so we don't need to invoke the
      // pop callbacks.
      PopMatch(false);
      break;
    }

    // Roll back the search front, and terminate the search if need be.
    directive = PopMatch(true);
    if (directive == kBrowserTerminateAll || directive == kBrowserAbort)
      break;
  }

  tag_lineage_.pop_back();
  symbol_lineage_.pop_back();

  return directive;
}

namespace builder {

typedef DiaBrowser::PatternBuilder PatternBuilder;

Proxy::Proxy()
    : pattern_builder_(new PatternBuilder()) {
}

Proxy::Proxy(const PatternBuilder& pb)
    : pattern_builder_(new PatternBuilder()) {
  pattern_builder_->CopyFrom(pb);
}

Proxy::Proxy(SymTag sym_tag)
    : pattern_builder_(new PatternBuilder(sym_tag)) {
}

Proxy::Proxy(SymTagBitSet sym_tags)
    : pattern_builder_(new PatternBuilder(sym_tags)) {
}

Proxy::~Proxy() {
  delete pattern_builder_;
}

Proxy Tag(SymTag sym_tag) {
  return Proxy(sym_tag);
}

Proxy Tags(SymTagBitSet sym_tags) {
  return Proxy(sym_tags);
}

Proxy Tags(SymTag st0, SymTag st1, SymTag st2, SymTag st3,
           SymTag st4, SymTag st5, SymTag st6, SymTag st7) {
  DCHECK(st0 != kSymTagInvalid);
  SymTagBitSet sym_tags;
  AddToSymTagBitSet(st0, &sym_tags);
  AddToSymTagBitSet(st1, &sym_tags);
  AddToSymTagBitSet(st2, &sym_tags);
  AddToSymTagBitSet(st3, &sym_tags);
  AddToSymTagBitSet(st4, &sym_tags);
  AddToSymTagBitSet(st5, &sym_tags);
  AddToSymTagBitSet(st6, &sym_tags);
  AddToSymTagBitSet(st7, &sym_tags);
  DCHECK(sym_tags.count() > 0);
  return Proxy(sym_tags);
}

Proxy Not(SymTagBitSet sym_tags) {
  return Proxy(~sym_tags);
}

Proxy Not(SymTag st0, SymTag st1, SymTag st2, SymTag st3,
          SymTag st4, SymTag st5, SymTag st6, SymTag st7) {
  DCHECK(st0 != kSymTagInvalid);
  SymTagBitSet sym_tags;
  AddToSymTagBitSet(st0, &sym_tags);
  AddToSymTagBitSet(st1, &sym_tags);
  AddToSymTagBitSet(st2, &sym_tags);
  AddToSymTagBitSet(st3, &sym_tags);
  AddToSymTagBitSet(st4, &sym_tags);
  AddToSymTagBitSet(st5, &sym_tags);
  AddToSymTagBitSet(st6, &sym_tags);
  AddToSymTagBitSet(st7, &sym_tags);
  // We don't DCHECK(sym_tags_.count() > 0) because it's possible and valid
  // for a Not(SymTagNull) to have created an empty SymTagBitSet. This will
  // fail on AddPattern, however.
  return Proxy(~sym_tags);
}

Proxy Seq(const Proxy& p0, const Proxy& p1, const Proxy& p2, const Proxy& p3,
          const Proxy& p4, const Proxy& p5, const Proxy& p6, const Proxy& p7) {
  DCHECK(p0->type() != PatternBuilder::kPatternNone);
  DCHECK(p1->type() != PatternBuilder::kPatternNone);
  PatternBuilder pb(PatternBuilder::kPatternSeq, p0, p1);
  if (p2->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p2));
  if (p3->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p3));
  if (p4->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p4));
  if (p5->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p5));
  if (p6->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p6));
  if (p7->type() != PatternBuilder::kPatternNone)
    pb.CopyFrom(PatternBuilder(PatternBuilder::kPatternSeq, pb, p7));
  return Proxy(pb);
}

Proxy Or(const Proxy& p0, const Proxy& p1, const Proxy& p2, const Proxy& p3,
         const Proxy& p4, const Proxy& p5, const Proxy& p6, const Proxy& p7) {
  DCHECK(p0->type() != PatternBuilder::kPatternNone);
  DCHECK(p1->type() != PatternBuilder::kPatternNone);
  // We use the OrBuilder as an optimization to make sure that Tags
  // PatternBuilders are accumulated and simplified.
  PatternBuilder pbor;
  PatternBuilder::OrBuilder(p0, p1, &pbor);
  if (p2->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p2, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  if (p3->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p3, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  if (p4->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p4, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  if (p5->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p5, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  if (p6->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p6, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  if (p7->type() != PatternBuilder::kPatternNone) {
    PatternBuilder pbtemp;
    PatternBuilder::OrBuilder(pbor, p7, &pbtemp);
    pbor.CopyFrom(pbtemp);
  }
  return Proxy(pbor);
}

Proxy Opt(const Proxy& p) {
  return Proxy(PatternBuilder(PatternBuilder::kPatternOpt, p));
}

Proxy Plus(const Proxy& p) {
  return Proxy(PatternBuilder(PatternBuilder::kPatternPlus, p));
}

Proxy Star(const Proxy& p) {
  return Proxy(PatternBuilder(PatternBuilder::kPatternStar, p));
}

Proxy Callback(const Proxy& p, const MatchCallback& push_callback) {
  return Proxy(PatternBuilder(*p, push_callback, MatchCallback()));
}

Proxy Callback(const Proxy& p,
               const MatchCallback& push_callback,
               const MatchCallback& pop_callback) {
  return Proxy(PatternBuilder(*p, push_callback, pop_callback));
}

}  // namespace builder

}  // namespace pe
