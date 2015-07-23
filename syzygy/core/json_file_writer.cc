// Copyright 2011 Google Inc. All Rights Reserved.
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
// JSONFileWriter works as a simple state machine. Rather than using an
// exhaustive set of states and a big switch, its encoded via a few state
// variables, and a handful of state determination functions. The general rule
// of thumb is that when output is produced we write as much as is possible.
#include "syzygy/core/json_file_writer.h"

#include <stdarg.h>

#include "base/logging.h"
#include "base/values.h"
#include "base/json/json_writer.h"
#include "base/json/string_escape.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/utf_string_conversions.h"

namespace core {

namespace {

using base::Value;

static const char kNewline[] = "\n";
static const char kIndent[] = "  ";
static const char kNull[] = "null";
static const char kTrue[] = "true";
static const char kFalse[] = "false";
static const char kCommentPrefix[] = "//";

static const char* kStructureOpenings[] = { "[", "{", NULL };
static const char* kStructureClosings[] = { "]", "}", NULL };

}  // namespace

struct JSONFileWriter::Helper {
  template<typename KeyType>
  static bool OutputKey(KeyType key, JSONFileWriter* json_file_writer) {
    DCHECK(json_file_writer != NULL);

    if (!json_file_writer->ReadyForKey())
      return false;

    if (!json_file_writer->AlignForValueOrKey())
      return false;

    std::string formatted_key = base::GetQuotedJSONString(key.as_string());
    if (!json_file_writer->Printf("%s:", formatted_key.c_str()))
      return false;

    // If we're pretty printing, then also output a space between the key and
    // the value.
    if (json_file_writer->pretty_print_ && !json_file_writer->PutChar(' '))
      return false;

    // Indicate that we've output a key and require a value.
    json_file_writer->stack_.push_back(StackElement(kDictKey));
    return true;
  }

  template<typename ValueType, typename PrintFunctionPointer>
  static bool OutputValue(ValueType value,
                          PrintFunctionPointer print_function,
                          JSONFileWriter* json_file_writer) {
    DCHECK(print_function != NULL);
    DCHECK(json_file_writer != NULL);

    if (!json_file_writer->ReadyForValue())
      return false;
    if (!json_file_writer->AlignForValueOrKey())
      return false;
    if (!(json_file_writer->*print_function)(value))
      return false;
    json_file_writer->FlushValue(true);
    return true;
  }
};

JSONFileWriter::JSONFileWriter(FILE* file, bool pretty_print)
    : file_(file),
      pretty_print_(pretty_print),
      finished_(false),
      at_col_zero_(true),
      indent_depth_(0) {
  DCHECK(file != NULL);
}

JSONFileWriter::~JSONFileWriter() {
  Flush();
}

bool JSONFileWriter::OutputComment(const base::StringPiece& comment) {
  // If we are in the middle of writing a dictionary key/value pair
  // (have the key, not the value), then we can't write a comment.
  if (RequireKeyValue())
    return false;

  // If we're not pretty-printing, this is a no-op.
  if (!pretty_print_)
    return true;

  // Trailing comments can be written directly.
  if (finished_) {
    if (!OutputNewline() || !Printf("%s", kCommentPrefix))
      return false;
    if (comment.length() > 0 &&
        !Printf(" %.*s", comment.length(), comment.data())) {
      return false;
    }
    return true;
  }

  // Store the comment for output before the next value.
  comments_.push_back(comment.as_string());

  return true;
}

bool JSONFileWriter::OutputComment(const base::StringPiece16& comment) {
  std::string utf8;
  if (!base::WideToUTF8(comment.data(), comment.length(), &utf8))
    return false;
  return OutputComment(utf8);
}

bool JSONFileWriter::OutputTrailingComment(const base::StringPiece& comment) {
  // A trailing comment can only go out after a value has been written.
  if (!stack_.empty()) {
    if (stack_.back().type_ == kDictKey)
      return false;

    if (stack_.back().has_entries_ == false)
      return false;
  } else {
    // If the stack is empty, then a value has only been written if we are
    // finished.
    if (!finished_)
      return false;
  }

  // No comment? Do nothing!
  if (comment.length() == 0)
    return true;

  // If we already have a trailing comment, bail!
  if (!trailing_comment_.empty())
    return false;

  // Save the comment for output when we're ready. We do this even when not
  // pretty-printing so that the state machine functions identically in either
  // case.
  trailing_comment_.assign(comment.begin(), comment.end());

  // Are we finished? Immediately write the comment, but leave
  // trailing_comment_ populated so that repeated calls will fail.
  if (finished_ &&
      !Printf("  %s %s", kCommentPrefix, trailing_comment_.c_str())) {
    return false;
  }

  return true;
}

bool JSONFileWriter::OutputTrailingComment(const base::StringPiece16& comment) {
  std::string utf8;
  if (!base::WideToUTF8(comment.data(), comment.length(), &utf8))
    return false;
  return OutputTrailingComment(utf8);
}

bool JSONFileWriter::PrintBoolean(bool value) {
  return Printf("%s", value ? kTrue : kFalse);
}

bool JSONFileWriter::PrintInteger(int value) {
  return Printf("%d", value);
}

bool JSONFileWriter::PrintDouble(double value) {
  base::FundamentalValue fundamental_value(value);
  return PrintValue(&fundamental_value);
}

bool JSONFileWriter::PrintString(const base::StringPiece& value) {
  return Printf("%s", base::GetQuotedJSONString(value.as_string()).c_str());
}

bool JSONFileWriter::PrintNull(int value_unused) {
  return Printf("%s", kNull);
}

bool JSONFileWriter::PrintValue(const Value* value) {
  DCHECK(value != NULL);

  switch (value->GetType()) {
    case Value::TYPE_LIST:
    case Value::TYPE_DICTIONARY: {
      // TODO(chrisha): Eventually, these should be implemented.
      LOG(ERROR) << "JSON Lists and Dictionaries are currently unsupported.";
      return false;
    }

    // All simple types.
    case Value::TYPE_BOOLEAN:
    case Value::TYPE_INTEGER:
    case Value::TYPE_DOUBLE:
    case Value::TYPE_NULL:
    case Value::TYPE_STRING:
    case Value::TYPE_BINARY: {
      std::string str;
      base::JSONWriter::Write(value, &str);
      return Printf("%s", str.c_str());
    }

    default: {
      NOTREACHED() << "Unexpected JSON type: " << value->GetType();
      return false;
    }
  }
}

bool JSONFileWriter::Printf(const char* format, ...) {
  va_list args;
  va_start(args, format);
  int chars_written = vfprintf(file_, format, args);
  va_end(args);
  if (chars_written > 0)
    at_col_zero_ = false;
  return chars_written >= 0;
}

bool JSONFileWriter::PutChar(char c) {
  if (fputc(c, file_) != c)
    return false;
  at_col_zero_ = false;
  return true;
}

bool JSONFileWriter::OpenList() {
  return OpenStructure(kList);
}

bool JSONFileWriter::CloseList() {
  return CloseStructure(kList);
}

bool JSONFileWriter::OpenDict() {
  return OpenStructure(kDict);
}

bool JSONFileWriter::CloseDict() {
  return CloseStructure(kDict);
}

bool JSONFileWriter::OutputKey(const base::StringPiece& key) {
  return Helper::OutputKey(key, this);
}

bool JSONFileWriter::OutputKey(const base::StringPiece16& key) {
  return Helper::OutputKey(key, this);
}

bool JSONFileWriter::Flush() {
  // Already finished? This is a no-op.
  if (finished_)
    return true;

  // Are we waiting on a required value?
  if (RequireKeyValue())
    return false;

  // Otherwise, simply close off the structures one by one.
  while (!stack_.empty()) {
    if (!CloseStructure(stack_.back().type_))
      return false;
  }

  return true;
}

bool JSONFileWriter::OutputBoolean(bool value) {
  return Helper::OutputValue(
      value, &JSONFileWriter::PrintBoolean, this);
}

bool JSONFileWriter::OutputInteger(int value) {
  return Helper::OutputValue(
      value, &JSONFileWriter::PrintInteger, this);
}

bool JSONFileWriter::OutputDouble(double value) {
  return Helper::OutputValue(
      value, &JSONFileWriter::PrintDouble, this);
}

bool JSONFileWriter::OutputString(const base::StringPiece& value) {
  return Helper::OutputValue(
      value, &JSONFileWriter::PrintString, this);
}

bool JSONFileWriter::OutputString(const base::StringPiece16& value) {
  std::string utf8;
  if (!base::WideToUTF8(value.data(), value.length(), &utf8))
    return false;
  return OutputString(utf8);
}

bool JSONFileWriter::OutputNull() {
  int unused = 0;
  return Helper::OutputValue(
      unused, &JSONFileWriter::PrintNull, this);
}

bool JSONFileWriter::OutputValue(const Value* value) {
  return Helper::OutputValue(
      value, &JSONFileWriter::PrintValue, this);
}

bool JSONFileWriter::OutputIndent() {
  if (!pretty_print_)
    return true;

  // We bypass Printf and manually update at_col_zero_ here for efficiency.
  if (indent_depth_ > 0)
    at_col_zero_ = false;
  for (size_t i = 0; i < indent_depth_; ++i) {
    if (fprintf(file_, "%s", kIndent) < 0)
      return false;
  }
  return true;
}

bool JSONFileWriter::OutputNewline() {
  if (!pretty_print_ || at_col_zero_)
    return true;

  // Bypass Printf and manually at_col_zero_ for efficiency.
  if (fprintf(file_, "%s", kNewline) < 0)
    return false;
  at_col_zero_ = true;

  return true;
}

bool JSONFileWriter::OutputComments() {
  if (comments_.empty())
    return true;

  // Comments are only stored if we're pretty-printing.
  DCHECK(pretty_print_);

  bool indented = at_col_zero_ == false;

  for (size_t i = 0; i < comments_.size(); ++i) {
    // Indent if need be.
    if (at_col_zero_ && !OutputIndent())
      return false;

    // Output the comment prefix.
    if (!Printf("%s", kCommentPrefix))
      return false;

    // Output the comment if there's any content.
    if (!comments_[i].empty() &&
        !Printf(" %s", comments_[i].c_str()))
      return false;

    if (!OutputNewline())
      return false;
  }

  // If we were indented when entering, indent on the way out.
  if (indented && !OutputIndent())
    return false;

  // Clear the comments.
  comments_.clear();

  return true;
}

bool JSONFileWriter::OutputTrailingComment() {
  if (trailing_comment_.empty())
    return true;

  // If we're pretty-printing, output the comment.
  if (pretty_print_ &&
      !Printf("  %s %s", kCommentPrefix, trailing_comment_.c_str())) {
    return false;
  }

  trailing_comment_.clear();

  return true;
}

bool JSONFileWriter::AlignForValueOrKey() {
  // Are we a dictionary key waiting for a value? If so, there's nothing to
  // do as the alignment was taken care of when the key was written.
  if (RequireKeyValue())
    return true;

  // Are we in a structure, and not the first entry? Then we need to
  // output a trailing comma.
  if (!stack_.empty() && !FirstEntry() && !PutChar(','))
    return false;

  // Are we not pretty-printing? Then we're done!
  if (!pretty_print_)
    return true;

  if (!OutputTrailingComment())
    return false;

  // Go to a new line if need be.
  if (!OutputNewline())
    return false;

  if (!OutputIndent())
    return false;

  return OutputComments();
}

bool JSONFileWriter::FirstEntry() const {
  if (stack_.empty())
    return true;
  return !stack_.back().has_entries_;
}

bool JSONFileWriter::ReadyForKey() const {
  if (stack_.empty())
    return false;
  return stack_.back().type_ == kDict;
}

bool JSONFileWriter::ReadyForValue() const {
  if (finished_)
    return false;
  if (stack_.empty())
    return true;
  return stack_.back().type_ != kDict;
}

bool JSONFileWriter::RequireKeyValue() const {
  if (stack_.empty())
    return false;
  return stack_.back().type_ == kDictKey;
}

bool JSONFileWriter::CanClose(StructureType type) const {
  // You can never 'close' a dict key.
  if (stack_.empty() || type == kDictKey)
    return false;
  return stack_.back().type_ == type;
}

bool JSONFileWriter::OpenStructure(StructureType type) {
  DCHECK_GT(arraysize(kStructureOpenings), static_cast<size_t>(type));
  DCHECK(kStructureOpenings[type] != NULL);

  if (!ReadyForValue() ||
      !AlignForValueOrKey() ||
      !Printf("%s", kStructureOpenings[type])) {
    return false;
  }

  // Opening a new structure is like writing a new value, but the value has
  // not been *finished*.
  FlushValue(false);

  stack_.push_back(StackElement(type));
  ++indent_depth_;

  return true;
}

bool JSONFileWriter::CloseStructure(StructureType type) {
  DCHECK_GT(arraysize(kStructureClosings), static_cast<size_t>(type));
  DCHECK(kStructureClosings[type] != NULL);

  if (!CanClose(type) ||
      !OutputTrailingComment() ||
      !OutputNewline() ||
      !OutputComments()) {
    return false;
  }

  stack_.pop_back();
  --indent_depth_;
  if (pretty_print_ && !OutputIndent())
    return false;

  if (!Printf("%s", kStructureClosings[type])) {
    return false;
  }

  // If this closed the last open structure, then the JSON file is finished.
  if (stack_.empty())
    finished_ = true;

  return true;
}

void JSONFileWriter::FlushValue(bool value_completed) {
  // The value was successfully written, so if we were in a dictionary waiting
  // for a value, pop the kDictKey entry off the stack.
  if (RequireKeyValue())
    stack_.pop_back();

  // If the stack is not empty, indicate that a value has been written to
  // the open structure.
  if (!stack_.empty()) {
    stack_.back().has_entries_ = true;
  } else {
    if (value_completed) {
      // If the stack is empty then having a written a single value means the
      // JSON file is finished.
      finished_ = true;
    }
  }
}

void JSONFileWriter::CompileAsserts() {
  COMPILE_ASSERT(
      arraysize(kStructureOpenings) == JSONFileWriter::kMaxStructureType,
      StructureOpenings_not_in_sync_with_StructureType_enum);
  COMPILE_ASSERT(
      arraysize(kStructureClosings) == JSONFileWriter::kMaxStructureType,
      StructureClosings_not_in_sync_with_StructureType_enum);
}

}  // namespace core
