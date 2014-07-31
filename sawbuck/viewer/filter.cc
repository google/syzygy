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
#include "base/values.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
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
  value_ = base::WideToUTF8(value);
  BuildRegExp();
}


Filter::Filter(const base::DictionaryValue* const serialized) : match_re_("") {
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

std::string Filter::value() const {
  return value_;
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

base::DictionaryValue* Filter::Serialize() const {
  scoped_ptr<base::DictionaryValue> filter_dict(new base::DictionaryValue());
  filter_dict->SetInteger("column", column_);
  filter_dict->SetInteger("relation", relation_);
  filter_dict->SetInteger("action", action_);
  filter_dict->SetString("value", value_);
  return filter_dict.release();
}

bool Filter::Deserialize(const base::DictionaryValue* const serialized) {
  // I wish I could make this data-driven. The static_casts needed because of
  // the use of enums makes this hard.
  if (!serialized->GetStringASCII("value", &value_)) {
    LOG(ERROR) << "Bad filter, no field named value.";
    return false;
  }

  int column = -1;
  if (serialized->GetInteger("column", &column) &&
      column > -1 && column < NUM_COLUMNS) {
    column_ = static_cast<Column>(column);
  } else {
    LOG(ERROR) << "Bad Filter, no column field.";
    return false;
  }

  int relation = -1;
  if (serialized->GetInteger("relation", &relation) &&
      relation > -1 && relation < NUM_RELATIONS) {
    relation_ = static_cast<Relation>(relation);
  } else {
    LOG(ERROR) << "Bad Filter, no relation field.";
    return false;
  }

  int action = -1;
  if (serialized->GetInteger("action", &action) &&
      action > -1 && action < NUM_ACTIONS) {
    action_ = static_cast<Action>(action);
  } else {
    LOG(ERROR) << "Bad Filter, no action field.";
    return false;
  }

  return true;
}

// static
std::vector<Filter> Filter::DeserializeFilters(const std::string& stored) {
  std::vector<Filter> filters;

  scoped_ptr<base::ListValue> filter_list_value;

  if (!stored.empty()) {
    scoped_ptr<base::Value> parsed_value(base::JSONReader::Read(stored, true));
    if (parsed_value.get() && parsed_value->IsType(base::Value::TYPE_LIST)) {
      filter_list_value.reset(
          static_cast<base::ListValue*>(parsed_value.release()));
    } else {
      LOG(ERROR) << "Failed to parse filter list: " << stored;
    }
  }

  if (filter_list_value.get() && filter_list_value->GetSize() > 0) {
    base::ListValue::const_iterator filter_iter(filter_list_value->begin());
    for (; filter_iter != filter_list_value->end(); ++filter_iter) {
      if ((*filter_iter)->IsType(base::Value::TYPE_DICTIONARY)) {
        Filter filter(static_cast<base::DictionaryValue*>(*filter_iter));
        if (filter.IsValid()) {
          filters.push_back(filter);
        }
      } else {
        LOG(ERROR) << "Unexpected filter type in filter list, type: "
                   << (*filter_iter)->GetType() << ", string: " << stored;
      }
    }
  }

  return filters;
}

// static
std::string Filter::SerializeFilters(const std::vector<Filter>& filters) {
  scoped_ptr<base::ListValue> filters_list(
      SerializeFiltersToListValue(filters));
  std::string serialized_string;
  base::JSONWriter::WriteWithOptions(
      filters_list.get(),
      base::JSONWriter::OPTIONS_PRETTY_PRINT,
      &serialized_string);
  return serialized_string;
}

// static
base::ListValue* Filter::SerializeFiltersToListValue(
    const std::vector<Filter>& filters) {
  scoped_ptr<base::ListValue> filters_list(new base::ListValue);
  std::vector<Filter>::const_iterator iter(filters.begin());
  for (; iter != filters.end(); ++iter) {
    filters_list->Append(iter->Serialize());
  }
  return filters_list.release();
}


bool Filter::operator==(const Filter& other) const{
  return other.column_ == column_ &&
         other.relation_ == relation_ &&
         other.action_ == action_ &&
         other.value_ == value_;
}
