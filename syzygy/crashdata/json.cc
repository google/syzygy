// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/crashdata/json.h"

// We use standard dependencies only, as we don't want to introduce a
// dependency on base into the backend crash processing code.
#include <assert.h>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace crashdata {

namespace {

const size_t kIndentSize = 2;

void IncreaseIndent(std::string* indent) {
  if (!indent)
    return;
  indent->append(kIndentSize, ' ');
}

void DecreaseIndent(std::string* indent) {
  if (!indent)
    return;
  indent->resize(indent->size() - kIndentSize);
}

void EmitIndent(std::string* indent, std::string* output) {
  assert(output != nullptr);
  if (!indent)
    return;
  output->append(*indent);
}

void EmitHexValue8(unsigned char value, std::string* output) {
  assert(output != nullptr);
  output->push_back('"');
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setfill('0') << std::setw(2)
      << std::uppercase << static_cast<unsigned int>(value);
  output->append(oss.str());
  output->push_back('"');
}

void EmitHexValue32(google::protobuf::uint64 value, std::string* output) {
  assert(output != nullptr);
  output->push_back('"');
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setfill('0') << std::setw(8)
      << std::uppercase << value;
  output->append(oss.str());
  output->push_back('"');
}

template <typename IntType>
void EmitDecValue(IntType value, std::string* output) {
  assert(output != nullptr);
  std::ostringstream oss;
  oss << std::dec << std::setw(0) << value;
  output->append(oss.str());
}

void EmitDouble(double value, std::string* output) {
  assert(output != nullptr);
  std::ostringstream oss;
  oss << std::scientific << std::setprecision(16) << std::uppercase << value;
  output->append(oss.str());
}

void EmitNull(std::string* output) {
  assert(output != nullptr);
  output->append("null");
}

void EmitString(const std::string& s, std::string* output) {
  assert(output != nullptr);
  output->reserve(output->size() + 2 + s.size());
  output->push_back('"');
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '"') {
      output->append("\\\"");
    } else if (s[i] == '\\') {
      output->append("\\\\");
    } else {
      output->push_back(s[i]);
    }
  }
  output->push_back('"');
}

// A helper for emitting a list like object. Calls the provided yield functor
// for each element.
template <typename YieldFunctor>
bool EmitJsonList(char open_bracket,
                  char close_bracket,
                  size_t items_per_line,
                  size_t item_count,
                  YieldFunctor& yield,
                  std::string* indent,
                  std::string* output) {
  assert(items_per_line > 0);
  assert(output != nullptr);

  // Open up the list, and indent if necessary.
  output->push_back(open_bracket);
  IncreaseIndent(indent);
  EmitIndent(indent, output);

  // Emit the stack frames.
  for (size_t i = 0; i < item_count; ++i) {
    if (!yield(i, indent, output))
      return false;

    // Emit a trailing comma for all entries but the last. For
    // the last entry reduce the indent amount to match the opening
    // bracket.
    if (i + 1 < item_count) {
      output->push_back(',');
    } else if (indent) {
      DecreaseIndent(indent);
    }

    // If at the last element in a line, or the last element in the list then
    // emit a line ending and indent.
    if ((i + 1) % items_per_line == 0 || i + 1 == item_count) {
      // Output the appropriate indent for the next line or the
      // closing bracket.
      EmitIndent(indent, output);
    } else if (indent != nullptr) {
      // Emit a single space for the next element if we're emitting whitespace.
      output->push_back(' ');
    }
  }

  // Close the list.
  output->push_back(close_bracket);
  return true;
}

// Emits a dictionary key, but not the value. Does not increase the indent
// for the value.
void EmitDictKey(const std::string& key,
                 std::string* indent,
                 std::string* output) {
  assert(output != nullptr);
  EmitString(key, output);
  output->push_back(':');
  if (indent)
    output->push_back(' ');
}

// Forward declaration of this, as it's the common container type for other
// values.
bool ToJson(const Value* value, std::string* indent, std::string* output);

bool ToJson(const Address* address, std::string* indent, std::string* output) {
  assert(address != nullptr);
  assert(output != nullptr);
  EmitHexValue32(address->address(), output);
  return true;
}

struct StackTraceYieldFunctor {
  explicit StackTraceYieldFunctor(const StackTrace* stack_trace)
      : stack_trace_(stack_trace) {
    assert(stack_trace != nullptr);
  }

  bool operator()(size_t index, std::string* indent, std::string* output) {
    assert(output != nullptr);
    assert(index <= std::numeric_limits<int>::max());
    EmitHexValue32(stack_trace_->frames().Get(static_cast<int>(index)), output);
    return true;
  }

  const StackTrace* stack_trace_;
};

bool ToJson(const StackTrace* stack_trace,
            std::string* indent,
            std::string* output) {
  assert(stack_trace != nullptr);
  assert(output != nullptr);
  StackTraceYieldFunctor yield(stack_trace);
  if (!EmitJsonList('[', ']', 4, stack_trace->frames_size(), yield,
                    indent, output)) {
    return false;
  }
  return true;
}

// A functor for emitting the binary data in a blob as an array.
struct BlobDataYieldFunctor {
  explicit BlobDataYieldFunctor(const Blob* blob)
      : blob_(blob) {
    assert(blob != nullptr);
  }

  bool operator()(size_t index, std::string* indent, std::string* output) {
    EmitHexValue8(static_cast<unsigned char>(blob_->data()[index]), output);
    return true;
  }

  const Blob* blob_;
};

// A functor for emitting the contents of a blob as a dictionary.
struct BlobYieldFunctor {
  explicit BlobYieldFunctor(const Blob* blob)
      : blob_(blob), need_comma_(false) {
    assert(blob != nullptr);
  }

  bool operator()(size_t index, std::string* indent, std::string* output) {
    assert(output != nullptr);
    switch (index) {
      case 0: {
        // Emit a blob descriptor.
        EmitDictKey("type", indent, output);
        EmitString("blob", output);
        return true;
      }
      case 1: {
        EmitDictKey("address", indent, output);
        if (blob_->has_address()) {
          if (!ToJson(&blob_->address(), indent, output))
            return false;
        } else {
          EmitNull(output);
        }
        return true;
      }
      case 2: {
        EmitDictKey("size", indent, output);
        if (blob_->has_size()) {
          EmitDecValue(blob_->size(), output);
        } else {
          EmitNull(output);
        }
        return true;
      }
      case 3: {
        EmitDictKey("data", indent, output);
        if (blob_->has_data()) {
          BlobDataYieldFunctor yield(blob_);
          if (!EmitJsonList('[', ']', 8, blob_->data().size(), yield,
                            indent, output)) {
            return false;
          }
        } else {
          EmitNull(output);
        }
        return true;
      }
      default: break;
    }

    // This should never happen!
    assert(false);
    return false;
  }

  const Blob* blob_;
  bool need_comma_;
};

bool ToJson(const Blob* blob, std::string* indent, std::string* output) {
  assert(blob != nullptr);
  assert(output != nullptr);
  BlobYieldFunctor yield(blob);
  // 1 element per line, 4 elements total.
  if (!EmitJsonList('{', '}', 1, 4, yield, indent, output))
    return false;
  return true;
}

bool ToJson(const Leaf* leaf, std::string* indent, std::string* output) {
  assert(leaf != nullptr);
  assert(output != nullptr);

  if (!leaf->has_type())
    return false;

  switch (leaf->type()) {
    default:
    case Leaf_Type_UNKNOWN_TYPE: {
      return false;
    }

    case Leaf_Type_INTEGER: {
      if (!leaf->has_integer())
        return false;
      EmitDecValue(leaf->integer(), output);
      return true;
    }

    case Leaf_Type_UNSIGNED_INTEGER: {
      if (!leaf->has_unsigned_integer())
        return false;
      EmitDecValue(leaf->unsigned_integer(), output);
      return true;
    }

    case Leaf_Type_REAL: {
      if (!leaf->has_real())
        return false;
      EmitDouble(leaf->real(), output);
      return true;
    }

    case Leaf_Type_STRING: {
      if (!leaf->has_string())
        return false;
      EmitString(leaf->string(), output);
      return true;
    }

    case Leaf_Type_ADDRESS: {
      if (!leaf->has_address())
        return false;
      if (!ToJson(&leaf->address(), indent, output))
        return false;
      return true;
    }

    case Leaf_Type_STACK_TRACE: {
      if (!leaf->has_stack_trace())
        return false;
      if (!ToJson(&leaf->stack_trace(), indent, output))
        return false;
      return true;
    }

    case Leaf_Type_BLOB: {
      if (!leaf->has_blob())
        return false;
      if (!ToJson(&leaf->blob(), indent, output))
        return false;
      return true;
    }
  }

  assert(false);
  return false;
}

struct ValueListYieldFunctor {
  explicit ValueListYieldFunctor(const ValueList* list) : list_(list) {}

  bool operator()(size_t index, std::string* indent, std::string* output) {
    assert(output != nullptr);
    assert(index <= std::numeric_limits<int>::max());
    if (!ToJson(&list_->values().Get(static_cast<int>(index)), indent, output))
      return false;
    return true;
  }

  const ValueList* list_;
};

bool ToJson(const ValueList* list, std::string* indent, std::string* output) {
  assert(list != nullptr);
  assert(output != nullptr);
  ValueListYieldFunctor yield(list);
  if (!EmitJsonList('[', ']', 1, list->values_size(), yield, indent, output))
    return false;
  return true;
}

bool ToJson(
    const KeyValue* key_value, std::string* indent, std::string* output) {
  assert(key_value != nullptr);
  assert(output != nullptr);
  if (!key_value->has_key())
    return false;
  if (!key_value->has_value())
    return false;
  EmitDictKey(key_value->key(), indent, output);
  if (!ToJson(&key_value->value(), indent, output))
    return false;
  return true;
}

struct DictYieldFunctor {
  explicit DictYieldFunctor(const Dictionary* dict) : dict_(dict) {
  }

  bool operator()(size_t index,
                  std::string* indent,
                  std::string* output) {
    assert(output != nullptr);
    assert(index <= std::numeric_limits<int>::max());
    if (!ToJson(&dict_->values().Get(static_cast<int>(index)), indent, output))
      return false;
    return true;
  }

  const Dictionary* dict_;
};

bool ToJson(const Dictionary* dict, std::string* indent, std::string* output) {
  assert(dict != nullptr);
  assert(output != nullptr);
  DictYieldFunctor yield(dict);
  if (!EmitJsonList('{', '}', 1, dict->values_size(), yield, indent, output))
    return false;
  return true;
}

bool ToJson(const Value* value, std::string* indent, std::string* output) {
  assert(value != nullptr);
  assert(output != nullptr);
  if (!value->has_type())
    return false;
  switch (value->type()) {
    default:
    case Value_Type_UNKNOWN_TYPE: {
      return false;
    }

    case Value_Type_LEAF: {
      if (!value->has_leaf())
        return false;
      if (!ToJson(&value->leaf(), indent, output))
        return false;
      return true;
    }

    case Value_Type_VALUE_LIST: {
      if (!value->has_list())
        return false;
      if (!ToJson(&value->list(), indent, output))
        return false;
      return true;
    }

    case Value_Type_DICTIONARY: {
      if (!value->has_dictionary())
        return false;
      if (!ToJson(&value->dictionary(), indent, output))
        return false;
      return true;
    }
  }

  assert(false);
  return false;
}

}  // namespace

bool ToJson(bool pretty_print, const Value* value, std::string* output) {
  assert(value != nullptr);
  assert(output != nullptr);
  std::string* indent = nullptr;
  std::string indent_content;
  if (pretty_print) {
    indent_content = "\n";
    indent = &indent_content;
  }

  // Produce the output to a temp variable, as partial output may be produced
  // in case of error.
  std::string temp;
  if (!ToJson(value, indent, &temp))
    return false;

  // Place the output in the desired string as efficiently as possible.
  if (output->empty()) {
    output->swap(temp);
  } else {
    output->append(temp);
  }

  return true;
}

}  // namespace crashdata
