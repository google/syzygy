// Copyright 2010 Google Inc.
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
// Filter implementation.

#include "sawbuck/viewer/filter.h"

#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "sawbuck/viewer/log_list_view.h"

using base::IntToString;
using base::IntToString16;
using base::StringToInt;

const wchar_t kSeparator[] = L"|";

Filter::Filter(Column column, Relation relation, Action action,
               const wchar_t* value)
    : column_(column), relation_(relation), action_(action), is_valid_(true),
      match_re_("") {
  DCHECK(column < NUM_COLUMNS && relation < NUM_RELATIONS &&
         action < NUM_ACTIONS && value != NULL);
  value_ = WideToUTF8(value);
  BuildRegExp();
}

Filter::Filter(const std::wstring& serialized) : match_re_("") {
  is_valid_ = Deserialize(serialized);
  BuildRegExp();
}

void Filter::BuildRegExp() {
  switch (column_) {
    case SEVERITY:
    case TIME:
    case FILE:
    case MESSAGE:
      match_re_ = pcrecpp::RE(value_.c_str(),
          PCRE_NEWLINE_ANYCRLF | PCRE_DOTALL | PCRE_UTF8 | PCRE_CASELESS);
      break;
  }
}

std::wstring Filter::value() const {
  return UTF8ToWide(value_);
}

bool Filter::Matches(ILogView* log_view, int row_index) const {
  DCHECK(log_view);

  bool matches = false;
  switch (column_){
    case PROCESS_ID: {
      matches = ValueMatchesInt(log_view->GetProcessId(row_index));
      break;
    }
    case THREAD_ID: {
      matches = ValueMatchesInt(log_view->GetThreadId(row_index));
      break;
    }
    case SEVERITY:
    case TIME: {
      LogViewFormatter formatter;
      std::string col_str;
      formatter.FormatColumn(log_view,
                             row_index,
                             static_cast<LogViewFormatter::Column>(column_),
                             &col_str);
      matches = ValueMatchesString(col_str);
      break;
    }
    case FILE: {
      matches = ValueMatchesString(log_view->GetFileName(row_index));
      break;
    }
    case LINE: {
      matches = ValueMatchesInt(log_view->GetLine(row_index));
      break;
    }
    case MESSAGE: {
      matches = ValueMatchesString(log_view->GetMessage(row_index));
      break;
    }
    default:
      NOTREACHED() << "Invalid column type in filter!";
  }
  return matches;
}

bool Filter::ValueMatchesInt(int check_value) const {
  bool matches = false;
  if (relation_ == IS) {
    int filter_int;
    StringToInt(value_, &filter_int);
    if (check_value == filter_int) {
      matches = true;
    }
  } else if (relation_ == CONTAINS) {
    std::string check_string(IntToString(check_value));
    if (check_string.find(value_) != std::string::npos) {
      matches = true;
    }
  }
  return matches;
}

bool Filter::ValueMatchesString(const std::string& check_string) const {
  DCHECK(!match_re_.pattern().empty());
  bool matches = false;
  if (relation_ == IS) {
    matches = match_re_.FullMatch(check_string);
  } else if (relation_ == CONTAINS) {
    matches = match_re_.PartialMatch(check_string);
  }
  return matches;
}

std::wstring Filter::Serialize() const {
  std::wstring serialized;
  serialized += IntToString16(column_);
  serialized += kSeparator;
  serialized += IntToString16(relation_);
  serialized += kSeparator;
  serialized += IntToString16(action_);
  serialized += kSeparator;
  serialized += value();
  return serialized;
}

// TODO(robertshield): Don't really need separators and the like. Simplify this.
bool Filter::Deserialize(const std::wstring& serialized) {
  std::vector<std::wstring> pieces;
  size_t num_pieces = Tokenize(serialized, kSeparator, &pieces);

  // Note that we allow things of the form "1|1|0|", which will leave
  // value_ empty.
  if (num_pieces < 3) {
    LOG(WARNING) << "Error deserializing filter string: " << serialized;
    return false;
  }

  int col;
  StringToInt(pieces[0], &col);
  column_ = static_cast<Column>(col);

  int rel;
  StringToInt(pieces[1], &rel);
  relation_ = static_cast<Relation>(rel);

  int act;
  StringToInt(pieces[2], &act);
  action_ = static_cast<Action>(act);

  std::wstring wide_value;
  for (size_t i = 3; i < num_pieces; i++) {
    wide_value += pieces[i];
    if (i < num_pieces - 1) {
      wide_value += kSeparator;
    }
  }

  value_ = WideToUTF8(wide_value);

  return true;
}

// TODO(robertshield): Consider separating filter strings with newlines instead
// of length-prefixing them.
std::vector<Filter> Filter::DeserializeFilters(const std::wstring& stored) {
  std::vector<Filter> filters;

  if (!stored.empty()) {
    size_t offset = 0;
    size_t next_filter_start;
    while ((next_filter_start = stored.find(kSeparator, offset)) !=
           std::wstring::npos) {
      int length = 0;
      bool success = StringToInt(
          std::wstring(stored.begin() + offset,
                       stored.begin() + next_filter_start), &length);
      if (!success || length + offset > stored.length()) {
        LOG(ERROR) << "Corrupt filter string!";
        return std::vector<Filter>();
      }

      // Skip the leading separator character.
      next_filter_start++;

      std::wstring filter_string(
          stored.begin() + next_filter_start,
          stored.begin() + next_filter_start + length);
      Filter f(filter_string);
      if (f.IsValid()) {
        filters.push_back(f);
      } else {
        LOG(ERROR) << "Corrupt filter!";
        return std::vector<Filter>();
      }

      offset = next_filter_start + length;
    }
  }

  return filters;
}

std::wstring Filter::SerializeFilters(const std::vector<Filter>& filters) {
  std::wstring serialized_string;

  std::vector<Filter>::const_iterator iter(filters.begin());
  for (; iter != filters.end(); ++iter) {
    std::wstring filter_string(iter->Serialize());
    serialized_string += IntToString16(filter_string.length());
    serialized_string += kSeparator;
    serialized_string += filter_string;
  }

  return serialized_string;
}

bool Filter::operator==(const Filter& other) const{
  return other.column_ == column_ &&
         other.relation_ == relation_ &&
         other.action_ == action_ &&
         other.value_ == value_;
}
