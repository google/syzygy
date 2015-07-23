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

#include "syzygy/pehacker/variables.h"

#include "base/logging.h"
#include "base/json/json_reader.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"

namespace pehacker {

namespace {

// Converts a variable to a string.
bool ConvertVariableToString(bool quote_strings,
                             const base::Value& value,
                             std::string* s) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), s);

  switch (value.GetType()) {
    case base::Value::TYPE_BOOLEAN: {
      bool b = false;
      CHECK(value.GetAsBoolean(&b));
      *s = b ? "1" : "0";
      return true;
    }

    case base::Value::TYPE_INTEGER: {
      int i = 0;
      CHECK(value.GetAsInteger(&i));
      *s = base::StringPrintf("%d", i);
      return true;
    }

    case base::Value::TYPE_STRING: {
      CHECK(value.GetAsString(s));
      if (quote_strings) {
        s->insert(s->begin(), 1, '"');
        s->append(1, '"');
      }
      return true;
    }

    default: {
      LOG(ERROR) << "Variables must be strings, booleans or integers.";
      return false;
    }
  }
}

// Expands |value| using the given |variables|, placing the result in
// |expanded|. |expanded| and |value| may refer to the same string. An
// initial expansion should pass in |depth| of 0, as this is used to limit
// the depth of the expansion. Returns true on success, false otherwise.
bool ExpandVariables(size_t depth,
                     const base::DictionaryValue& variables,
                     const std::string& value,
                     std::string* expanded) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), expanded);

  VLOG(1) << "Expanding variables in \"" << value << "\" (depth="
          << depth << ").";

  std::string temp;

  // Arbitrarily limit ourselves to a recursion depth of 100.
  if (depth > 100) {
    LOG(ERROR) << "Recursion too deep in variable expansion of \""
               << value << "\".";
    return false;
  }

  // Scan through the input looking for $(var_name) sequences.
  size_t open = std::string::npos;
  size_t i = 0;
  while (i < value.size()) {
    // Reading normal string data, keeping an eye out for an opening delimiter.
    if (open == std::string::npos) {
      if (value[i] == '$') {
        // Handle $$ and $( sequences.
        if (i + 1 < value.size()) {
          // Two $$ are treated as a single literal $.
          if (value[i + 1] == '$') {
            i += 2;
            temp.append(1, '$');
            continue;
          } else if (value[i + 1] == '(') {
            // A $( is treated as the opening of a variable name.
            i += 2;
            open = i;
            continue;
          }
        }

        // If we get here then we have a trailing $, or a $ not followed by
        // a $ or a (. These are all malformed.
        LOG(ERROR) << "Expect $$ or $( in \"" << value << "\".";
        return false;
      }

      // If we get here we're simply appending the character to the output.
      temp.append(1, value[i]);
      i += 1;
      continue;
    }

    // If we get here we're reading a variable name, waiting for a closing
    // parenthesis.
    if (value[i] == ')') {
      // Lookup the variable name and recursively expand it. We limit
      // recursion depth to deal with circular definitions.
      std::string name(value.begin() + open, value.begin() + i);

      // Ensure the variable name is valid. This rejects invalid characters,
      // empty names, etc.
      if (!VariableNameIsValid(name)) {
        LOG(ERROR) << "Invalid variable name \"" << name << "\" in \""
                   << value << "\".";
        return false;
      }

      const base::Value* value = NULL;
      if (!variables.Get(name, &value)) {
        LOG(ERROR) << "Variable \"" << name << "\" not defined.";
        return false;
      }

      // Convert the variable to a string representation, which is the final
      // type of all variables.
      std::string s1;
      if (!ConvertVariableToString(false, *value, &s1))
        return false;

      // Recursively expand.
      std::string s2;
      if (!ExpandVariables(depth + 1, variables, s1, &s2))
        return false;

      // Append the expanded value.
      temp.append(s2);

      // Transition back to reading normal characters.
      open = std::string::npos;
    }

    // This steps past the close parenthesis, or a character that is part of
    // a variable name.
    i += 1;
  }

  // If waiting for a closing parenthesis then the string is malformed.
  if (open != std::string::npos) {
    LOG(ERROR) << "Unbalanced parentheses in value \"" << value << "\".";
    return false;
  }

  // Swap the expanded result with the output. This allows 'in-place' expansion
  // where |expanded| and |value| refer to the same string.
  expanded->swap(temp);

  VLOG(1) << "Expanded to \"" << *expanded << "\" (depth=" << depth << ").";

  return true;
}

}  // namespace

bool VariableNameIsValid(const std::string& name) {
  if (name.empty())
    return false;

  for (size_t i = 0; i < name.size(); ++i) {
    if (name[i] == '_' || ::isalnum(name[i]))
      continue;
    return false;
  }

  return true;
}

bool ConvertVariableToString(const base::Value& value, std::string* s) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), s);
  if (!ConvertVariableToString(false, value, s))
    return false;
  return true;
}

bool ConvertVariableToJson(const base::Value& value, std::string* s) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), s);
  if (!ConvertVariableToString(true, value, s))
    return false;
  return true;
}

bool ParseVariable(const std::string& raw_name,
                   const base::Value& value,
                   base::DictionaryValue* dict) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), dict);

  std::string name = raw_name;

  // Remove any modifiers.
  bool set_default = false;
  if (name.back() == '%') {
    set_default = true;
    name.resize(name.size() - 1);
  }

  if (!VariableNameIsValid(name)) {
    LOG(ERROR) << "Invalid variable name \"" << name << "\".";
    return false;
  }

  if (dict->HasKey(name)) {
    if (set_default) {
      VLOG(1) << "Ignoring default value for already set variable \""
              << name << "\".";
      return true;
    } else {
      LOG(ERROR) << "Variable already defined \"" << name << "\".";
      return false;
    }
  }

  // For now we only accept simple types that are unambiguously converted to
  // strings.
  if (value.GetType() != base::Value::TYPE_STRING &&
      value.GetType() != base::Value::TYPE_BOOLEAN &&
      value.GetType() != base::Value::TYPE_INTEGER) {
    LOG(ERROR) << "Variables must be strings, booleans or integers.";
    return false;
  }

  // Finally, set the value of the variable. Ownership is passed to the
  // dictionary.
  VLOG(1) << "Setting " << (set_default ? "default " : "") << "value of \""
          << name << "\" to " << value;
  dict->Set(name, value.DeepCopy());
  return true;
}

bool ParseVariable(const std::string& raw_name,
                   const std::string& value_string,
                   base::DictionaryValue* dict) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), dict);

  // Parse the value. We first try to parse it as valid JSON. If that
  // fails we treat it as a raw string.
  scoped_ptr<base::Value> value;
  value.reset(base::JSONReader::Read(value_string, 0));
  if (value.get() == NULL)
    value.reset(new base::StringValue(value_string));

  if (!ParseVariable(raw_name, *value.get(), dict))
    return false;
  return true;
}

bool MergeVariables(const base::DictionaryValue& src,
                    base::DictionaryValue* dst) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), dst);

  // Iterate over the values in the source dictionary and add them to the
  // destination dictionary. This logs verbosely on failure, and handles
  // variable directives (default values, etc).
  base::DictionaryValue::Iterator it(src);
  for (; !it.IsAtEnd(); it.Advance()) {
    if (!ParseVariable(it.key(), it.value(), dst))
      return false;
  }

  return true;
}

bool ExpandVariables(const base::DictionaryValue& variables,
                     const std::string& value,
                     std::string* expanded) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), expanded);
  if (!ExpandVariables(0, variables, value, expanded))
    return false;
  return true;
}

}  // namespace pehacker
