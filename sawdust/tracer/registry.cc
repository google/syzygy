// Copyright 2011 Google Inc.
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
// Class encapsulating extraction of registry information. Selected (through
// configuration) keys are written out into an output stream.
#include "sawdust/tracer/registry.h"

#include <algorithm>
#include <strstream>  // NOLINT - streams used as abstracts, without formatting.

#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"

namespace {

bool CompareNoCase(const std::wstring& lhv, const std::wstring& rhv) {
  return ::_wcsicmp(lhv.c_str(), rhv.c_str()) <= 0;
}
};

// Implementation of a text stream which feeds itself directly on the system
// registry, yielding its content as defined in the query.
// Essentially, this is where most of the realwork is done.
class RegistryExtractor::RegistryStreamBuff : public std::streambuf {
 public:
  explicit RegistryStreamBuff(const EntriesCollection& pass_entries,
                              const std::vector<std::wstring>& missing_data)
      : source_queue_(pass_entries), current_op_buffer_index_(0),
        formal_buffer_tail_(formal_buffer_), missing_(missing_data) {
  }

 protected:
  std::streambuf* setbuf(char_type* s, std::streamsize n) {
    return NULL;  // Do nothing. It is permitted.
  }

  std::streambuf::int_type underflow() {
    if (gptr() == NULL || gptr() >= egptr()) {
      if (LoadFormalBuffer()) {
        setg(formal_buffer_, formal_buffer_, formal_buffer_tail_);
        return traits_type::to_int_type(*formal_buffer_);
      } else {
        return traits_type::eof();
      }
    } else {
      DCHECK(gptr() >= formal_buffer_ && gptr() < formal_buffer_ + kBufferSize);
      return traits_type::to_int_type(*gptr());
    }
  }

  // Load data into the formal buffer from operation_buffer_. If operation
  // buffer is used up, need to produce some more data.
  bool LoadFormalBuffer() {
    if (operation_buffer_.empty() ||
        current_op_buffer_index_ >= operation_buffer_.size()) {
      GetMoreData();
    }

    if (operation_buffer_.empty())
      return false;  // No data produced, we are done.

    DCHECK(current_op_buffer_index_ >= 0 &&
           current_op_buffer_index_ < operation_buffer_.size());

    std::string::iterator src_iterator = operation_buffer_.begin() +
                                         current_op_buffer_index_;
    std::string::iterator end_iterator;

    if (operation_buffer_.end() - src_iterator < kBufferSize)
      end_iterator = operation_buffer_.end();
    else
      end_iterator = src_iterator + kBufferSize;

    formal_buffer_tail_ = std::copy(src_iterator, end_iterator, formal_buffer_);
    current_op_buffer_index_ = static_cast<std::string::size_type>(
        end_iterator - operation_buffer_.begin());
    return true;
  }

  // Advance the processing by munching the item on the stack.
  void GetMoreData() {
    operation_buffer_.clear();
    current_op_buffer_index_ = 0;

    if (current_stack_.empty()) {
      if (!source_queue_.empty()) {
        current_stack_.push_back(source_queue_.front());
        source_queue_.pop_front();
      }
    }

    if (current_stack_.empty())
      return;  // Nothing to do.

    EntriesCollection stack_tack;

    // The 'stack' concept here is a bit abused. Since I want to take advantage
    // of RegKey iteration, I will list each element's sub-keys right away and
    // tuck them to the stack-o-list (in reverse order). This will give me a
    // depth-first behavior without the need to remember the iterator state.
    const ScanEntryDef& this_entry = current_stack_.back();

    if (!this_entry.value_name_.empty()) {
      // An easy one. Just output the key data. Since value entries other than
      // these find in the input list are never put on stack, we don't need to
      // worry here about indentation.
      DCHECK_EQ(this_entry.indent_, unsigned(0));
      std::string formatted_value;
      base::win::RegKey parent_key(this_entry.root_, this_entry.path_.c_str(),
                                   KEY_READ);
      if (parent_key.Valid() &&
          parent_key.ValueExists(this_entry.value_name_.c_str())) {
        if (!CreateFormattedRegValue(&parent_key,
                                     this_entry.value_name_.c_str(), 0,
                                     &formatted_value)) {
          formatted_value = "ERROR: could not retrieve the value!";
        }
      } else {
        formatted_value = "ERROR: the value is GONE!";
      }

      operation_buffer_.reserve(formatted_value.size() + 64 +
                                2 * (this_entry.path_.size() +
                                     this_entry.value_name_.size()));
      base::SStringPrintf(&operation_buffer_, "%s\\%s\\%s\t(%s)\n",
                          this_entry.root_name_.c_str(),
                          WideToUTF8(this_entry.path_).c_str(),
                          WideToUTF8(this_entry.value_name_).c_str(),
                          formatted_value.c_str());
    } else {
      // Here, we need to employ iterators walking over values and keys.
      base::win::RegKey values_key(this_entry.root_,
                                   this_entry.path_.c_str(), KEY_READ);
      int value_count = values_key.ValueCount();

      // First size guesstimate.
      operation_buffer_.reserve(256 + 128 * value_count);

      if (this_entry.indent_ > 0) {
        std::wstring::const_reverse_iterator last_segment_it =
            std::find(this_entry.path_.rbegin(),
                      this_entry.path_.rend(), L'\\');

        std::wstring last_segment(last_segment_it.base(),
                                  this_entry.path_.end());
        operation_buffer_.append(this_entry.indent_, '\t');
        operation_buffer_.append(WideToUTF8(last_segment));
        operation_buffer_.append(1, '\n');
      } else {
        base::SStringPrintf(&operation_buffer_, "%s\\%s\n",
                            this_entry.root_name_.c_str(),
                            WideToUTF8(this_entry.path_).c_str());
      }

      std::wstring value_name;
      std::string formatted_value;
      for (int i = 0;
           i < value_count &&
           ERROR_SUCCESS == values_key.ReadName(i, &value_name); ++i) {
        operation_buffer_.append(this_entry.indent_ + 1, '\t');
        std::string formatted_val;
        if (CreateFormattedRegValue(&values_key, value_name.c_str(),
                                    this_entry.indent_ + 2, &formatted_val)) {
          base::StringAppendF(&operation_buffer_, "%s\t(%s)\n",
                              WideToUTF8(value_name).c_str(),
                              formatted_val.c_str());
        } else {
          operation_buffer_.append(WideToUTF8(value_name));
          operation_buffer_.append("\t(Failed to extract the value)\n");
        }
      }

      // Having written out all values, we now list all child entries.
      base::win::RegistryKeyIterator keys(this_entry.root_,
                                          this_entry.path_.c_str());
      while (keys.Valid()) {
        stack_tack.push_back(ScanEntryDef());
        ScanEntryDef& new_entry = stack_tack.back();
        new_entry.indent_ = this_entry.indent_ + 1;
        new_entry.root_ = this_entry.root_;
        new_entry.path_ = this_entry.path_;
        new_entry.path_ += L'\\';
        new_entry.path_ += keys.Name();

        ++keys;
      }
    }

    current_stack_.pop_back();
    // Normally we would insert in opposite order. However, RegistryKeyIterator
    // walks in the reverse order (comparing to what we would normally see in
    // regedit). Thus, it is enough to just tuck the list to the end.
    current_stack_.insert(current_stack_.end(),
                          stack_tack.begin(), stack_tack.end());

    if (current_stack_.empty() && source_queue_.empty())
      AppendErrorList();
  }

  void AppendErrorList() {
    if (missing_.empty())
      return;
    operation_buffer_.reserve(operation_buffer_.size() +
                              missing_.size() * 256 + 64);

    base::StringAppendF(&operation_buffer_,
                        "\n%s\n", "Keys / values not found:");

    for (std::vector<std::wstring>::const_iterator it = missing_.begin();
         it != missing_.end(); ++it) {
      operation_buffer_.append(1, '\t');
      operation_buffer_.append(WideToUTF8(*it));
      operation_buffer_.append(1, '\n');
    }
  }

 private:
  static const int kBufferSize = 4096;
  char formal_buffer_[kBufferSize];
  char* formal_buffer_tail_;  // Points behind the actual data in the buffer.

  // Inflatable buffer into which text will be first put.
  std::string operation_buffer_;
  // Points behind data loaded into formal.
  std::string::size_type current_op_buffer_index_;

  EntriesCollection source_queue_;
  EntriesCollection current_stack_;
  std::vector<std::wstring> missing_;
};

RegistryExtractor::RegistryExtractor() : own_data_stream_(NULL) {
}

void RegistryExtractor::Reset() {
  validated_root_entries_.clear();
  missing_entries_.clear();
}

// The routine tries to break the string first as a key path and then as a value
// path. The first one that works (and can be read) will be inserted into the
// instance of ScanEntryDef. If none of these entries can be created, the
// function will return false.
// As an (intended) side effect of the implementation, the function will fail
// when the path has less than three levels.
bool RegistryExtractor::VerifiedEntryFromString(const std::wstring& full_path,
                                                ScanEntryDef* entry) {
  DCHECK(entry != NULL);
  std::wstring::const_iterator first_div =
      std::find(full_path.begin(), full_path.end(), L'\\');
  std::wstring::const_reverse_iterator last_div_r =
      std::find(full_path.rbegin(), full_path.rend(), L'\\');

  // This check the assumption there are at least three nesting levels. For
  // instance, we don't allow entire HKLM\SOFTWARE to be harvested.
  // last_div_r iterator may be used later, to separate key path form value
  // name.
  if (last_div_r == full_path.rend() || last_div_r.base() == first_div) {
    LOG(WARNING) << "Incorrect registry path syntax: " << full_path;
    return false;
  }

  std::wstring root_name(full_path.begin(), first_div);
  std::wstring key_path(first_div + 1, full_path.end());

  // Convert the root_name to a HKEY value;
  HKEY root_handle = NULL;
  if (root_name == L"HKEY_LOCAL_MACHINE")
    root_handle = HKEY_LOCAL_MACHINE;
  else if (root_name == L"HKEY_CURRENT_USER")
    root_handle = HKEY_CURRENT_USER;
  else if (root_name == L"HKEY_CLASSES_ROOT")
    root_handle = HKEY_CLASSES_ROOT;
  else if (root_name == L"HKEY_CURRENT_CONFIG")
    root_handle = HKEY_CURRENT_CONFIG;
  else  // We don't do HKEY_USERS intentionally.
    LOG(WARNING) << "Incorrect root key: " << root_name;

  if (root_handle == NULL)
    return false;

  base::win::RegKey reg_key;

  std::wstring value_buffer;
  if (ERROR_SUCCESS == reg_key.Open(root_handle, key_path.c_str(), KEY_READ)) {
    entry->root_ = root_handle;
    entry->value_name_.clear();
    entry->path_ = key_path;
    entry->root_name_ = WideToASCII(root_name);
  } else {
    // A key at key_path does not exist, but perhaps a value does.
    std::wstring subkey_or_value(last_div_r.base(), full_path.end());
    key_path = std::wstring(first_div + 1, last_div_r.base() - 1);

    if (ERROR_SUCCESS == reg_key.Open(root_handle,
                                      key_path.c_str(), KEY_READ) &&
        reg_key.ValueExists(subkey_or_value.c_str())) {
      entry->root_ = root_handle;
      entry->value_name_ = subkey_or_value;
      entry->path_ = key_path;
      entry->root_name_ = WideToASCII(root_name);
    } else {
      LOG(WARNING) << "Cannot open the requested registry path: " << full_path;
      return false;
    }
  }
  return true;
}

int RegistryExtractor::Initialize(
    const std::vector<std::wstring>& input_container) {
  int pass_counter = 0;

  std::vector<std::wstring> container_copy(input_container);
  std::sort(container_copy.begin(), container_copy.end(), CompareNoCase);

  std::wstring previous_inserted;
  for (std::vector<std::wstring>::const_iterator it = container_copy.begin();
       it != container_copy.end(); ++it) {
    ScanEntryDef new_entry;
    if (!VerifiedEntryFromString(*it, &new_entry)) {
      // If it doesn't exist, we certainly care enough to register.
      missing_entries_.push_back(*it);
      continue;
    }

    if (!previous_inserted.empty() && previous_inserted.size() <= it->size()) {
      // If the previous entry is a prefix (ignoring case) of the current item,
      // we will disregard it. It has already been processed.
      if (StartsWith(*it, previous_inserted, false))
        continue;
    }

    validated_root_entries_.push_back(new_entry);
    previous_inserted = *it;
    ++pass_counter;
  }

  current_streambuff_.reset(new RegistryStreamBuff(validated_root_entries_,
                                                   missing_entries_));
  own_data_stream_.rdbuf(current_streambuff_.get());
  return pass_counter;
}

std::istream& RegistryExtractor::Data() {
  DCHECK(own_data_stream_.rdbuf() == current_streambuff_.get());
  return own_data_stream_;
}

void RegistryExtractor::MarkCompleted() {
  DCHECK(own_data_stream_.rdbuf() == current_streambuff_.get());
  current_streambuff_.reset(new RegistryStreamBuff(validated_root_entries_,
                                                   missing_entries_));
  own_data_stream_.rdbuf(current_streambuff_.get());
}

bool RegistryExtractor::FormatBinaryValue(const char* buffer,
                                          size_t buffer_size,
                                          std::string* formatted_output) {
  if (formatted_output == NULL || buffer == NULL || buffer_size == 0) {
    NOTREACHED() << "Invalid parameters";
    return false;
  }

  formatted_output->reserve(3 * buffer_size + 1);
  const char* last = buffer + buffer_size;
  char symbol[4] = "00 ";
  for (;buffer < last; ++buffer) {
    char ch = (*buffer & 0xF0) >> 4;
    symbol[0] = ch > 9 ? ('A' + ch - 10) : '0' + ch;
    ch = (*buffer & 0x0F);
    symbol[1] = ch > 9 ? ('A' + ch - 10) : '0' + ch;
    formatted_output->append(symbol);
  }

  formatted_output->resize(formatted_output->size() - 1, 0);  // Lose the space.

  return true;
}

bool RegistryExtractor::FormatMultiStringValue(const wchar_t* buffer,
                                               size_t buf_length, int indent,
                                               std::string* formatted_utf8) {
  if (formatted_utf8 == NULL || buffer == NULL || buf_length == 0) {
    NOTREACHED() << "Invalid parameters";
    return false;
  }
  // Note that buf_length is in 'iterator steps'.
  const wchar_t* mstring_word_start = buffer;
  const wchar_t* mstring_end = buffer + buf_length;
  while (*mstring_word_start != 0 && mstring_word_start != mstring_end) {
    const wchar_t* mstring_word_end = std::find(mstring_word_start,
                                                mstring_end, 0);
    std::wstring subsection(mstring_word_start, mstring_word_end);
    if (mstring_word_start != buffer) {
      formatted_utf8->append(1, '\n');
      formatted_utf8->append(indent, '\t');
    }
    formatted_utf8->append(WideToUTF8(subsection));
    // Move beyond the found iterator. It is correct because mstring_word_end
    // will never be mstring_end since each member string finishes by 0.
    mstring_word_start = mstring_word_end + 1;
  }
  return true;
}

bool RegistryExtractor::CreateFormattedRegValue(base::win::RegKey* key,
                                                const wchar_t* value_name,
                                                int multiline_indent,
                                                std::string* formatted_utf8) {
  if (key == NULL && value_name == NULL && formatted_utf8 == NULL) {
    NOTREACHED() << "Invalid parameters. Fix it.";
    return false;
  }
  const size_t kMaxStringLength = 1024;
  wchar_t raw_value[kMaxStringLength];
  scoped_array<wchar_t> auxiliary_buffer;
  wchar_t* utility_buffer = raw_value;

  DWORD type = REG_SZ;
  DWORD size = sizeof(raw_value);
  bool succeeded = key->ReadValue(value_name,
                                  reinterpret_cast<void*>(utility_buffer),
                                  &size, &type) == ERROR_SUCCESS;

  if (!succeeded && size > sizeof(raw_value)) {
    size_t alloc_size = size + (size % sizeof(wchar_t));
    auxiliary_buffer.reset(new wchar_t[alloc_size / 2]);
    size = alloc_size;
    utility_buffer = auxiliary_buffer.get();
    succeeded = key->ReadValue(value_name,
                               reinterpret_cast<void*>(utility_buffer),
                               &size, &type) == ERROR_SUCCESS;
  }

  if (succeeded) {
    formatted_utf8->clear();
    switch (type) {
      case REG_DWORD: {
        DCHECK_EQ(size, size_t(4));  // REG_DWORD is 32-bit, by doc.
        uint32* cast_buff = reinterpret_cast<uint32*>(utility_buffer);
        // No need to worry about endian-ness. It is windows and little-endian
        // has a separate type.
        base::SStringPrintf(formatted_utf8, "0x%0*X", 8, *cast_buff);
        break;
      }
      case REG_QWORD: {
        DCHECK_EQ(size, size_t(8));  // REG_QWORD is 64-bit, by doc.
        uint64* cast_buff = reinterpret_cast<uint64*>(utility_buffer);
        base::SStringPrintf(formatted_utf8, "0x%0*I64X", 16, *cast_buff);
        break;
      }
      case REG_SZ: {
        DCHECK_EQ(size % 2, size_t(0));
        // Give length without the trailing zero.
        succeeded = WideToUTF8(utility_buffer, size / 2 - 1, formatted_utf8);
        break;
      }
      case REG_EXPAND_SZ: {
        size_t required_length = ExpandEnvironmentStrings(utility_buffer,
                                                          NULL, 0);
        if (required_length > 0) {
          required_length += 2;
          wchar_t* expand_buffer = reinterpret_cast<wchar_t*>(
              malloc(required_length * sizeof(wchar_t)));
          size_t copy_length = ExpandEnvironmentStrings(utility_buffer,
                                                        expand_buffer,
                                                        required_length);
          // Success: returns the number of wchar_t's copied
          // Fail: buffer too small, returns the size required
          // Fail: other, returns 0
          succeeded = (copy_length > 0 || copy_length <= required_length);
          if (succeeded) {
            succeeded = WideToUTF8(expand_buffer, copy_length - 1,
                                   formatted_utf8);
          }
          free(expand_buffer);
        }

        break;
      }
      case REG_MULTI_SZ: {
        DCHECK_EQ(size % sizeof(wchar_t), size_t(0));
        succeeded = FormatMultiStringValue(utility_buffer,
                                           size / sizeof(wchar_t),
                                           multiline_indent, formatted_utf8);
        break;
      }
      case REG_BINARY: {
        succeeded = FormatBinaryValue(reinterpret_cast<char*>(utility_buffer),
                                      size, formatted_utf8);
        break;
      }
      default:
        // A type we don't care about. Will have to give an error message.
        base::SStringPrintf(formatted_utf8, "Type 0x%X not supported.", type);
        break;
    }
  }

  return succeeded;
}
