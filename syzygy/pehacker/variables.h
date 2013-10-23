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
// Defines utilities for handling dictionaries of variables and performing
// variable expansion. JSON values are used for storage as this is intended
// for handling variables in JSON configuration files.

#ifndef SYZYGY_PEHACKER_VARIABLES_H_
#define SYZYGY_PEHACKER_VARIABLES_H_

#include "base/values.h"

namespace pehacker {

// Determines if a variable name is valid. Names must be alpha-numeric, and may
// also contain the _ character.
// @param name The name to evaluate.
// @returns true if the given variable name is valid.
bool VariableNameIsValid(const std::string& name);

// Converts a variable to a string. This logs an error on failure.
// @param value The value to be converted.
// @param s The string to be populated.
// @returns true on success, false otherwise.
bool ConvertVariableToString(const base::Value& value, std::string* s);

// Converts a variable to a JSON-parseable representation of it. This logs an
// error on failure.
// @param value The value to be converted.
// @param s The string to be populated.
// @returns true on success, false otherwise.
bool ConvertVariableToJson(const base::Value& value, std::string* s);

// Parses a variable, updating a dictionary of variables with its value. This
// handles variable directives suffixed to the name of the variable. This logs
// an error on failure.
//
// Variable directive suffixes:
//
//   %: Default value. If the value doesn't exist in the dictionary, set it with
//      the provided value. If it does already exist, ignore the value being
//      parsed and keep the existing value.
//
// @param name The name of the variable.
// @param value The parsed value of the variable.
// @param value_string The unparsed value of the variable. This will be parsed
//     as a JSON encoded string. If that fails, it will be treated as a raw
//     string.
// @param dict The dictionary in which the variable will be stored.
// @returns true on success, false otherwise.
bool ParseVariable(const std::string& name,
                   const base::Value& value,
                   base::DictionaryValue* dict);
bool ParseVariable(const std::string& name,
                   const std::string& value_string,
                   base::DictionaryValue* dict);

// Merges two dictionaries of variables. The variables names of the source
// dictionary will be parsed for variable directives (ie: % for default) value
// and handled appropriately. This logs an error on failure.
// @param src The source dictionary. Keys in this dictionary may be suffixed
//     with variable directives.
// @param dst The destination dictionary. Already existing keys in this
//     dictionary must not have suffixes, and new keys added will be stripped of
//     any suffixes.
// @returns true on success, false otherwise.
bool MergeVariables(const base::DictionaryValue& src,
                    base::DictionaryValue* dst);

// Expands a value using the given dictionary of variables. This logs an error
// on failure.
// @param variables The variables to use in expansion.
// @param value The value to be expanded.
// @param expanded The string to be populated with the expanded value. This may
//     refer to the same string as |value| for in-place expansion.
// @returns true on success, false otherwise.
bool ExpandVariables(const base::DictionaryValue& variables,
                     const std::string& value,
                     std::string* expanded);

}  // namespace pehacker

#endif  // SYZYGY_PEHACKER_VARIABLES_H_
