// Copyright 2013 Google Inc. All Rights Reserved.
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
// Declares FilterCompiler, a utility class for converting textual descriptions
// of symbols/compilands/etc into address-space filters for a given image.
//
// A filter description consists of a series of rules of the form:
//
//   [+ or -][type]:[description]
//
// A line with a leading '+' means that any address ranges matching the rule
// will be added to the filter. A line with a leading '-' means that the
// corresponding address ranges will be removed from the filter. Lines will be
// processed in the order that they are provided in the file.
//
// The types that are currently recognized are:
//
//   function       Matches undecorated function names. The description is a
//                  regex that will be matched against the symbol name,
//                  including its full namespace.
//   public_symbol  Allows matching of public symbols. The description is a
//                  regex that will be matched against the decorated symbol
//                  name.
//
// Comments may be specified using the '#' character.

#ifndef SYZYGY_GENFILTER_FILTER_COMPILER_H_
#define SYZYGY_GENFILTER_FILTER_COMPILER_H_

#include <dia2.h>
#include <map>

#include "pcrecpp.h"  // NOLINT
#include "syzygy/pe/image_filter.h"

namespace genfilter {

class FilterCompiler {
 public:
  typedef core::RelativeAddress RelativeAddress;
  typedef pe::ImageFilter ImageFilter;
  typedef ImageFilter::RelativeAddressFilter RelativeAddressFilter;
  typedef RelativeAddressFilter::Range Range;

  // Possible modification types.
  enum ModificationType {
    // The bytes matching the rule will be added to the filter.
    kAddToFilter,
    // The bytes matching the rule will be subtracted from the filter.
    kSubtractFromFilter,
  };

  // Possible filter rule types.
  enum RuleType{
    kFunctionRule,
    kPublicSymbolRule,

    // This must be last.
    kRuleTypeCount,
  };

  // Constructor.
  FilterCompiler() { }

  // @name Accessors.
  // @{
  const base::FilePath& image_path() const { return image_path_; }
  const base::FilePath& pdb_path() const { return pdb_path_; }
  // @}

  // Initializes this filter generator. Logs verbosely on failure.
  // @param image_path The path to the image for which a filter is being
  //     generated.
  // @param pdb_path The path of the corresponding PDB. If this is empty it
  //     will be searched for.
  // @returns true on success, false otherwise.
  // @note Init must be called before calling any other member functions.
  bool Init(const base::FilePath& image_path);
  bool Init(const base::FilePath& image_path, const base::FilePath& pdb_path);

  // Adds a rule to this filter compiler.
  // @param modification_type The way the filter is modifed upon successful
  //     matching of this rule.
  // @param rule_type The type of the rule to add.
  // @param description The rule description. This must be a valid Perl regex
  //     pattern.
  // @returns true on success, false otherwise.
  bool AddRule(ModificationType modification_type,
               RuleType rule_type,
               const base::StringPiece& description);

  // Parses a filter description file, adding its contents to this compiler.
  // Logs verbosely on failure.
  // @param path The path of the filter description file to parse.
  // @returns true on success, false otherwise.
  bool ParseFilterDescriptionFile(const base::FilePath& path);

  // Compiles a filter using the current rules. This logs a warning for any
  // filter rules that were not successfully matched.
  // @param filter The filter to be populated.
  // @returns true on success, false otherwise.
  bool Compile(ImageFilter* filter);

 protected:
  // Forward declaration.
  struct Rule;

  typedef pcrecpp::RE RE;
  typedef std::map<size_t, Rule> RuleMap;
  typedef std::vector<Rule*> RulePointers;

  // Adds a rule with explicit source information to this filter compiler.
  // @param modification_type The way the filter is modified upon successful
  //     matching of this rule.
  // @param rule_type The type of the rule to add.
  // @param description The rule description. This must be a valid Perl regex
  //     pattern.
  // @param source_info A description of the source file, line number and
  //     content. This is only used during error reporting.
  // @returns true on success, false otherwise.
  bool AddRule(ModificationType modification_type,
               RuleType rule_type,
               const base::StringPiece& description,
               const base::StringPiece& source_info);

  // Crawls the symbols matching rules. Delegates to the various symbol
  // visitors.
  // @returns true on success, false otherwise.
  bool CrawlSymbols();

  // Fills in the filter using cached symbol match data in the rules.
  // @param filter The filter to be filled in.
  bool FillFilter(ImageFilter* filter);

  // @name Symbol visitors.
  // @{
  bool OnCompiland(IDiaSymbol* compiland);
  bool OnFunction(IDiaSymbol* function);
  bool OnPublicSymbol(IDiaSymbol* public_symbol);
  // @}

  // Matches a symbol by name against rules in the given vector. Called by
  // OnPublicSymbol and OnFunction.
  // @param rules The vector of rules to be inspected for a symbol match.
  // @param symbol The symbol to inspect.
  bool MatchRulesBySymbolName(const RulePointers& rules, IDiaSymbol* symbol);

  base::FilePath image_path_;
  base::FilePath pdb_path_;
  pe::PEFile::Signature image_signature_;

  // Stores the filter lines in a map, keyed by their index. We use a map so
  // that pointers are stable.
  RuleMap rule_map_;

  // Rule pointers stored by type. This allows efficient access while crawling
  // symbols
  RulePointers rules_by_type_[kRuleTypeCount];

  DISALLOW_COPY_AND_ASSIGN(FilterCompiler);
};

struct FilterCompiler::Rule {
  // Constructor.
  Rule(size_t index,
       ModificationType modification_type,
       RuleType rule_type,
       const pe::PEFile::Signature& image_signature,
       const base::StringPiece& regex,
       const base::StringPiece& source_info)
      : index(index),
        modification_type(modification_type),
        rule_type(rule_type),
        ranges(Range(RelativeAddress(0), image_signature.module_size)),
        regex(regex.as_string()),
        source_info(source_info.as_string()) {
  }

  // The index of the filter. This reflects the order in which it was added to
  // the compiler.
  size_t index;

  // The type of modification that this rule will enact.
  ModificationType modification_type;

  // The type of filter rule.
  RuleType rule_type;

  // The ranges of the image covered by this filter line. The rules may be
  // matched and satisfied in an arbitrary order while crawling the symbols and
  // this is used to persist the filter information so that it may be applied in
  // the intended order once symbol resolution is complete.
  RelativeAddressFilter ranges;

  // The regex pattern associated with this filter line.
  RE regex;

  // The source information associated with the rule. This is for debugging.
  std::string source_info;
};

}  // namespace genfilter

#endif  // SYZYGY_GENFILTER_FILTER_COMPILER_H_
