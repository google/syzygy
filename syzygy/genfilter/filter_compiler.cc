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

#include "syzygy/genfilter/filter_compiler.h"

#include <stdio.h>

#include "base/bind.h"
#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_com_initializer.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"

namespace genfilter {

namespace {

const char kFunction[] = "function";
const char kPublicSymbol[] = "public_symbol";

const char* kRuleTypeStrings[] = { kFunction, kPublicSymbol };
COMPILE_ASSERT(arraysize(kRuleTypeStrings) == FilterCompiler::kRuleTypeCount,
               kRuleTypeStrings_out_of_sync_with_RuleType_enum);

// Read a newline terminated line from a file. The newline is part of the
// returned string.
bool ReadLine(FILE* file, std::string* line) {
  DCHECK(file != NULL);
  DCHECK(line != NULL);

  line->clear();
  while (true) {
    errno = 0;
    int c = ::fgetc(file);
    if (c == EOF) {
      if (errno != 0)
        return false;
      return true;
    }

    line->append(1, static_cast<char>(c));
    if (c == '\n')
      return true;
  }
}

// Trims any comments from the provided string.
void TrimComment(std::string* s) {
  DCHECK(s != NULL);
  size_t comment_index = s->find_first_of('#');
  if (comment_index == std::string::npos)
    return;

  s->resize(comment_index);
}

}  // namespace

bool FilterCompiler::Init(const base::FilePath& image_path) {
  return Init(image_path, base::FilePath());
}

bool FilterCompiler::Init(const base::FilePath& image_path,
                          const base::FilePath& pdb_path) {
  image_path_ = image_path;
  pdb_path_ = pdb_path;

  // Get the PDB path if none was provided.
  if (pdb_path_.empty()) {
    // This logs verbosely for us on failure.
    if (!pe::FindPdbForModule(image_path_, &pdb_path_))
      return false;

    if (pdb_path_.empty()) {
      LOG(ERROR) << "Unable to find PDB for image: " << image_path_.value();
      return false;
    }
  } else {
    // If a PDB path was provided make sure it matches the image file.
    if (!pe::PeAndPdbAreMatched(image_path_, pdb_path_)) {
      LOG(ERROR) << "PDB file \"" << pdb_path_.value() << "\" does not match "
                 << "image file \"" << image_path_.value() << "\".";
      return false;
    }
  }

  // Get the module signature.
  pe::PEFile pe_file;
  if (!pe_file.Init(image_path)) {
    LOG(ERROR) << "Unable to read module: " << image_path_.value();
    return false;
  }
  pe_file.GetSignature(&image_signature_);

  return true;
}

bool FilterCompiler::AddRule(ModificationType modification_type,
                             RuleType rule_type,
                             const base::StringPiece& description) {
  DCHECK_LE(0, rule_type);
  DCHECK_GT(kRuleTypeCount, rule_type);

  // Generate source information for this rule.
  std::string source_info("(no source file): ");
  source_info.append(1, modification_type == kAddToFilter ? '+' : '-');
  source_info.append(kRuleTypeStrings[rule_type]);
  source_info.append(1, ':');
  source_info.append(description.as_string());

  if (!AddRule(modification_type, rule_type, description, source_info))
    return false;

  return true;
}

bool FilterCompiler::ParseFilterDescriptionFile(const base::FilePath& path) {
  base::ScopedFILE file(base::OpenFile(path, "rb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open \"" << path.value() << "\" for reading.";
    return false;
  }

  static const RE kRuleRegex("^([+-])\\s*([a-zA-Z_]+)\\s*:\\s*(.+)$");

  // Convert the path to ASCII.
  std::string path_utf8 = base::WideToUTF8(path.value());

  // Process the file one line at a time.
  std::string line;
  size_t line_number = 0;
  size_t rules_added = 0;
  while (!::feof(file.get())) {
    ++line_number;
    if (!ReadLine(file.get(), &line)) {
      LOG(ERROR) << "Error reading from \"" << path.value() << "\".";
      return false;
    }
    TrimComment(&line);
    base::TrimWhitespace(line, base::TRIM_ALL, &line);

    // Skip empty lines.
    if (line.empty())
      continue;

    // Parse the rule.
    std::string mod, type, desc;
    if (!kRuleRegex.FullMatch(line, &mod, &type, &desc)) {
      LOG(ERROR) << "Unable to parse rule at line " << line_number
                 << " of \"" << path.value() << "\".";
      LOG(ERROR) << "  Content: " << line;
      return false;
    }

    // We are guaranteed that |mod| is "+" or "-" if the regex matches.
    DCHECK_EQ(1u, mod.size());
    ModificationType mod_type =
        (mod[0] == '+' ? kAddToFilter : kSubtractFromFilter);

    // Get the rule type.
    RuleType rule_type = kFunctionRule;
    StringToLowerASCII(&type);
    if (type == kFunction) {
      rule_type = kFunctionRule;
    } else if (type == kPublicSymbol) {
      rule_type = kPublicSymbolRule;
    } else {
      LOG(ERROR) << "Unknown rule type \"" << type << "\" at line "
                 << line_number << " of \"" << path.value() << "\".";
      return false;
    }

    // Generate the source information. This is so that we can have meaningful
    // log messages.
    std::string source_info(path_utf8);
    source_info.append(base::StringPrintf("(%d): ", line_number));
    source_info.append(line);

    // Add the rule.
    DCHECK(!desc.empty());
    if (!AddRule(mod_type, rule_type, desc, source_info))
      return false;
    ++rules_added;
  }

  LOG(INFO) << "Added " << rules_added << " rule(s) from \"" << path.value()
            << "\".";

  return true;
}

bool FilterCompiler::Compile(ImageFilter* filter) {
  DCHECK(filter != NULL);

  if (!CrawlSymbols())
    return false;

  if (!FillFilter(filter))
    return false;

  return true;
}

bool FilterCompiler::AddRule(ModificationType modification_type,
                             RuleType rule_type,
                             const base::StringPiece& description,
                             const base::StringPiece& source_info) {
  DCHECK_LE(0, rule_type);
  DCHECK_GT(kRuleTypeCount, rule_type);

  size_t index = rule_map_.size();
  Rule rule(index, modification_type, rule_type, image_signature_,
            description, source_info);

  if (!rule.regex.error().empty()) {
    LOG(ERROR) << "Error adding rule.";
    LOG(ERROR) << "  Source: " << source_info;
    LOG(ERROR) << "  Error: " << rule.regex.error();
    return false;
  }

  RuleMap::iterator rule_it =
      rule_map_.insert(std::make_pair(index, rule)).first;
  Rule* rule_ptr = &rule_it->second;

  // Update the vectors of rules by type.
  rules_by_type_[rule_type].push_back(rule_ptr);

  return true;
}

bool FilterCompiler::CrawlSymbols() {
  // We can bail early if there's no work to do.
  if (rule_map_.empty())
    return true;

  base::win::ScopedComPtr<IDiaDataSource> data_source;
  if (!pe::CreateDiaSource(data_source.Receive()))
    return false;

  base::win::ScopedComPtr<IDiaSession> session;
  if (!pe::CreateDiaSession(pdb_path_, data_source, session.Receive()))
    return false;

  // Visit all compilands looking for symbols if we need to.
  if (!rules_by_type_[kFunctionRule].empty()) {
    pe::CompilandVisitor compiland_visitor(session);
    if (!compiland_visitor.VisitAllCompilands(
            base::Bind(&FilterCompiler::OnCompiland,
                       base::Unretained(this)))) {
      return false;
    }
  }

  // Visit public symbols if necessary.
  if (!rules_by_type_[kPublicSymbolRule].empty()) {
    // Grab the global scope
    base::win::ScopedComPtr<IDiaSymbol> global;
    HRESULT hr = session->get_globalScope(global.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to get the DIA global scope: "
                 << common::LogHr(hr) << ".";
      return false;
    }

    pe::ChildVisitor public_symbol_visitor(global, SymTagPublicSymbol);
    if (!public_symbol_visitor.VisitChildren(
            base::Bind(&FilterCompiler::OnPublicSymbol,
                       base::Unretained(this)))) {
      return false;
    }
  }

  return true;
}

bool FilterCompiler::FillFilter(ImageFilter* filter) {
  DCHECK(filter != NULL);

  filter->signature = image_signature_;
  filter->filter = RelativeAddressFilter(
      Range(RelativeAddress(0), image_signature_.module_size));

  RuleMap::const_iterator it = rule_map_.begin();
  size_t unmatched_rules = 0;
  for (; it != rule_map_.end(); ++it) {
    const Rule& rule = it->second;
    if (rule.ranges.empty()) {
      ++unmatched_rules;
      LOG(WARNING) << "Unmatched rule: " << rule.source_info;
      continue;
    }

    // Update the global filter with ranges matching this rule.
    if (rule.modification_type == kAddToFilter) {
      filter->filter.Union(rule.ranges, &filter->filter);
    } else {
      DCHECK_EQ(kSubtractFromFilter, rule.modification_type);
      filter->filter.Subtract(rule.ranges, &filter->filter);
    }
  }

  if (unmatched_rules)
    LOG(WARNING) << "There were " << unmatched_rules << " unmatched rule(s).";

  return true;
}

bool FilterCompiler::OnCompiland(IDiaSymbol* compiland) {
  DCHECK(compiland != NULL);
  pe::ChildVisitor function_visitor(compiland, SymTagFunction);
  if (!function_visitor.VisitChildren(
          base::Bind(&FilterCompiler::OnFunction,
                     base::Unretained(this)))) {
    return false;
  }
  return true;
}

bool FilterCompiler::OnFunction(IDiaSymbol* function) {
  DCHECK(function != NULL);
  if (!MatchRulesBySymbolName(rules_by_type_[kFunctionRule], function))
    return false;
  return true;
}

bool FilterCompiler::OnPublicSymbol(IDiaSymbol* public_symbol) {
  DCHECK(public_symbol != NULL);
  if (!MatchRulesBySymbolName(rules_by_type_[kPublicSymbolRule], public_symbol))
    return false;
  return true;
}

bool FilterCompiler::MatchRulesBySymbolName(const RulePointers& rules,
                                            IDiaSymbol* symbol) {
  DCHECK(symbol != NULL);

  // Get the symbol properties.
  base::win::ScopedBstr name_bstr;
  DWORD rva = 0;
  ULONGLONG length = 0;
  HRESULT hr = E_FAIL;
  if ((hr = symbol->get_name(name_bstr.Receive())) != S_OK ||
      (hr = symbol->get_relativeVirtualAddress(&rva)) != S_OK ||
      (hr = symbol->get_length(&length)) != S_OK) {
    // For some public symbols get_relativeVirtualAddress fails. We can safely
    // ignore these failures.
    return true;
  }

  // Convert the name to ASCII.
  std::string name;
  if (!base::WideToUTF8(name_bstr, name_bstr.Length(), &name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8: "
               << common::ToString(name_bstr);
    return false;
  }

  // Look for any matching rules and update the associated image ranges.
  RulePointers::const_iterator it = rules.begin();
  for (; it != rules.end(); ++it) {
    Rule* rule = *it;
    if (rule->regex.FullMatch(name))
      rule->ranges.Mark(Range(RelativeAddress(rva), length));
  }

  return true;
}

}  // namespace genfilter
