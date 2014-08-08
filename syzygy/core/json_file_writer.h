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
// JSONFileWriter is a lightweight class for writing JSON formatted output
// directly to file rather than via a base::Value intermediate and then
// std::string intermediate representation.
#ifndef SYZYGY_CORE_JSON_FILE_WRITER_H_
#define SYZYGY_CORE_JSON_FILE_WRITER_H_

#include <vector>
#include "base/basictypes.h"
#include "base/strings/string_piece.h"

// Forward declaration.
namespace base {
class Value;
}

namespace core {

// Class allowing std::ostream like output for formatted JSON serialization.
// Doesn't force use of Value or std::string intermediaries like JSONWriter
// does.
class JSONFileWriter {
 public:
  explicit JSONFileWriter(FILE* file, bool pretty_print);

  ~JSONFileWriter();

  bool pretty_print() const { return pretty_print_; }

  // Returns true if the stream is finished, and unable to accept further
  // data. Comments may still be output, however.
  bool Finished() const { return finished_; }

  // For outputting comments. A comment will appear on a line by itself, with
  // the same indentation as the next written value. Naturally, this means that
  // a comment attached to a value should be written prior to that value being
  // output. Multiple comments may be written successively. Comments are only
  // output if pretty printing is enabled. It is an error to output a comment
  // after a dictionary key has been written, but before the corresponding
  // value.
  bool OutputComment(const base::StringPiece& comment);
  bool OutputComment(const base::StringPiece16& comment);

  // For outputting a trailing comment. Only a single trailing comment may be
  // written for any given line. This may only be called after having written
  // a value.
  bool OutputTrailingComment(const base::StringPiece& comment);
  bool OutputTrailingComment(const base::StringPiece16& comment);

  // For outputting lists.
  bool OpenList();
  bool CloseList();

  // For outputting dictionaries.
  bool OpenDict();
  bool CloseDict();
  bool OutputKey(const base::StringPiece& key);
  bool OutputKey(const base::StringPiece16& key);

  // Closes off the JSON stream, terminating any open data structures.
  // Returns true on success, false on failure.
  bool Flush();

  // For outputting simple values.
  bool OutputBoolean(bool value);
  bool OutputInteger(int value);
  bool OutputDouble(double value);
  bool OutputString(const base::StringPiece& value);
  bool OutputString(const base::StringPiece16& value);
  bool OutputNull();

  // For compatibility with base::Value and base::JSONWriter.
  bool OutputValue(const base::Value* value);

 protected:
  // Everything here is protected for unittesting purposes.

  // Forward declarations.
  enum StructureType;
  struct StackElement;

  // This class is made our friend so that we can hide some templated
  // implementation details in the .cc file.
  struct Helper;
  friend struct Helper;

  // The following group of functions are for white-space and comments, and
  // their behaviour is different depending on whether or not we are pretty-
  // printing.

  // Outputs the current indent.
  bool OutputIndent();
  // Outputs a new line, but only if at_col_zero_ == false and if we're pretty
  // printing.
  bool OutputNewline();
  // Outputs any stored comments. Will leave the alignment in the same state it
  // found it: if at_col_zero_ is true when entering, it will be when exiting.
  // If at_col_zero_ is false on entering, it assumes the current indent is
  // already applied, and it will apply it again before exiting.
  bool OutputComments();
  bool OutputTrailingComment();
  // Aligns the output cursor for a value or for dictionary key.
  bool AlignForValueOrKey();

  // For printing an actual value. These are used by the templated
  // implementation of the various Output* functions.
  bool PrintBoolean(bool value);
  bool PrintInteger(int value);
  bool PrintDouble(double value);
  bool PrintString(const base::StringPiece& value);
  bool PrintNull(int value_unused);
  bool PrintValue(const base::Value* value);

  // The following group of functions act as pass-through for fprintf and fputc,
  // but update internal state. No newline characters should be written using
  // this mechanism. All newlines should be written using OutputNewline.
  bool Printf(const char* format, ...);
  bool PutChar(char c);

  // Some state determination functions.
  bool FirstEntry() const;
  bool ReadyForKey() const;
  bool ReadyForValue() const;
  bool RequireKeyValue() const;
  bool CanClose(StructureType type) const;

  // Outputs the beginning of a data structure.
  bool OpenStructure(StructureType type);
  // Outputs the end of a data structure.
  bool CloseStructure(StructureType type);
  // Performs any state changes necessary after outputting a value.
  void FlushValue(bool value_completed);

  static void CompileAsserts();

  // The file that is being written to.
  FILE* file_;
  // Indicates whether or not we are pretty printing.
  bool pretty_print_;
  // This is set when the stream writer is finished. That is, a single value
  // has been fully written to the stream. No more values will be accepted.
  bool finished_;
  // This indicates whether or not we have any output on the current line.
  bool at_col_zero_;
  // Stores the current depth of indentation.
  size_t indent_depth_;
  // Stores the stack of currently opened structures.
  std::vector<StackElement> stack_;
  // Stores any comments that are due to be output. We have to keep them
  // around because we don't know if we need to end the previous value with
  // a trailing comma or not.
  std::string trailing_comment_;
  std::vector<std::string> comments_;

  DISALLOW_COPY_AND_ASSIGN(JSONFileWriter);
};

// Enumerates the type of structures that may be present in JSON data. These
// are present here so that the unittests may make use of them.
enum JSONFileWriter::StructureType {
  // Used to indicate that we are currently in a list, and awaiting a
  // value.
  kList,
  // Used to indicate that we are currently in a dictionary, and awaiting
  // a value.
  kDict,
  // Used to indicate that we a dictionary key has been output, and that
  // we are currently awaiting a value.
  kDictKey,
  // This must always be the last entry!
  kMaxStructureType
};

// Used for indicating the type and state of an open JSON structure.
struct JSONFileWriter::StackElement {
  explicit StackElement(StructureType type)
      : type_(type), has_entries_(false) {
  }

  // The type of this element.
  StructureType type_;

  // Initialized to false. Update to true if a value has been output to the
  // structure represented by this stack element.
  bool has_entries_;
};

}  // namespace core

#endif  // SYZYGY_CORE_JSON_FILE_WRITER_H_
