// Copyright 2012 Google Inc. All Rights Reserved.
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
// Implements an experimental command line tool that tallies the amount
// of object code contributed to an executable by function and source line,
// as well as data size contributed by object files.
// The tool writes its output in JSON format for easy downstream processing.

#include "syzygy/experimental/code_tally/code_tally.h"

#include <cstdio>

#include "base/bind.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/win/pe_image.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_com_initializer.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"

namespace {

// Output the details of the executable.
bool WriteExecutableDict(const pe::PEFile::Signature& image_signature,
                         FileVersionInfo* image_version_info,
                         core::JSONFileWriter* writer) {
  if (!writer->OutputKey("executable") ||
      !writer->OpenDict()) {
    return false;
  }

  base::FilePath image_name = base::FilePath(image_signature.path).BaseName();
  if (!writer->OutputComment("The name of the image file.") ||
      !writer->OutputKey("name") ||
      !writer->OutputString(image_name.value())) {
    return false;
  }

  if (!writer->OutputComment("The image file's version.") ||
      !writer->OutputKey("version") ||
      !writer->OutputString(image_version_info->product_version())) {
    return false;
  }

  std::string time_stamp(
      base::StringPrintf("0x%llX", image_signature.module_time_date_stamp));

  if (!writer->OutputComment("The image file's date/time stamp.") ||
      !writer->OutputKey("timestamp") ||
      !writer->OutputString(time_stamp)) {
    return false;
  }

  // Close the executable dictionary.
  if (!writer->CloseDict())
    return false;

  return true;
}

bool GetImageSignature(const base::FilePath& image_name,
                       pe::PEFile::Signature* image_signature) {
  pe::PEFile image_file;
  if (!image_file.Init(image_name)) {
    LOG(ERROR) << "Unable to read image file '" << image_name.value() << "'.";

    return false;
  }
  image_file.GetSignature(image_signature);

  return true;
}

}  // namespace

CodeTally::CodeTally(const base::FilePath& image_file)
    : image_file_(image_file) {
}

bool CodeTally::TallyLines(const base::FilePath& pdb_file) {
  base::FilePath found_pdb = pdb_file;

  // Start by locating the PDB file, if one was not provided.
  if (found_pdb.empty() && !pe::FindPdbForModule(image_file_, &found_pdb)) {
    LOG(ERROR) << "Unable to find PDB file for image '"
               << image_file_.value() << "'.";
    return false;
  }

  // Make sure the PDB file, whether found or provided, matches the image file.
  if (!pe::PeAndPdbAreMatched(image_file_, found_pdb)) {
    LOG(ERROR) << "PDB file '" << found_pdb.value() << "' does not match "
               << " image file '" << image_file_.value() << "'.";
    return false;
  }

  // Retrieve the version info for the image file.
  image_file_version_.reset(
      FileVersionInfo::CreateFileVersionInfo(image_file_));
  if (image_file_version_.get() == NULL) {
    LOG(ERROR) << "Unable to get file version for image file '"
               << image_file_.value() << "'.";
    return false;
  }

  if (!GetImageSignature(image_file_, &image_signature_))
    return false;

  base::win::ScopedComPtr<IDiaDataSource> data_source;
  HRESULT hr = data_source.CreateInstance(CLSID_DiaSource);
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to create DIA source: " << common::LogHr(hr);
    return false;
  }
  hr = data_source->loadDataFromPdb(found_pdb.value().c_str());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to load PDB: " << common::LogHr(hr);
    return false;
  }

  hr = data_source->openSession(session_.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Unable to open session: " << common::LogHr(hr);
    return false;
  }

  pe::CompilandVisitor visitor(session_);
  if (!visitor.VisitAllCompilands(base::Bind(&CodeTally::OnCompilandPassOne,
                                        base::Unretained(this)))) {
    return false;
  }
  if (!visitor.VisitAllCompilands(base::Bind(&CodeTally::OnCompilandPassTwo,
                                              base::Unretained(this)))) {
    return false;
  }

  return true;
}

bool CodeTally::GenerateJsonOutput(core::JSONFileWriter* writer) {
  DCHECK(image_file_version_.get() != NULL);

  if (!writer->OpenDict())
    return false;

  if (!WriteExecutableDict(image_signature_, image_file_version_.get(), writer))
    return false;

  // Output all source files as an array and note their position for
  // later reference.
  if (!writer->OutputKey("sources"))
    return false;

  if (!writer->OpenList())
    return false;

  std::map<const SourceFileInfo*, size_t> source_file_ids;
  SourceFileInfoMap::const_iterator src_it(source_files_.begin());
  for (; src_it != source_files_.end(); ++src_it) {
    const SourceFileInfo* source_info = &src_it->second;
    if (!writer->OutputString(source_info->file_name))
      return false;

    // Allocate 0-based IDs to the source files.
    size_t next_id = source_file_ids.size();
    source_file_ids[source_info] = next_id;
  }

  if (!writer->CloseList())
    return false;

  // Now output all object files, and the source contributions within them.

  if (!writer->OutputKey("objects"))
    return false;

  if (!writer->OpenDict())
    return false;

  ObjectFileInfoMap::const_iterator obj_it(object_files_.begin());
  for (; obj_it != object_files_.end(); ++obj_it) {
    if (!writer->OutputKey(obj_it->second.file_name))
      return false;

    if (!writer->OpenDict())
      return false;

    const FunctionInfoAddressSpace& funs = obj_it->second.functions;
    FunctionInfoAddressSpace::const_iterator fun_it(funs.begin());
    for (; fun_it != funs.end(); ++fun_it) {
      const FunctionInfo& fun = fun_it->second;
      if (!writer->OutputKey(fun.name))
        return false;

      if (!writer->OpenDict())
        return false;

    // Tally the function's size.
    const FunctionRange& fun_range = fun_it->first;
    double fun_size = 0.0;
    for (size_t i = 0; i < fun_range.size(); ++i) {
      size_t offs = fun_range.start() + i;
      // If there's no recorded line use for the location,
      // this function is the sole contributor of the byte.
      if (offs >= use_counts_.size() || use_counts_[offs] == 0)
        fun_size += 1.0;
      else
        fun_size += 1.0 / use_counts_[offs];
    }

      // Output the function's size.
      if (!writer->OutputKey("size") ||
          !writer->OutputDouble(fun_size)) {
        return false;
      }

      // Tally up the line contribs to source file/line.
      typedef std::map<size_t, double> LineContribMap;
      typedef std::map<const SourceFileInfo*, LineContribMap> SourceContribMap;
      SourceContribMap source_contribs;
      for (size_t i = 0; i < fun.line_info.size(); ++i) {
        const FunctionInfo::LineData& line = fun.line_info[i];

        source_contribs[line.source_file][line.line] += line.code_bytes;
      }

      if (!source_contribs.empty()) {
        if (!writer->OutputKey("contribs"))
          return false;

        if (!writer->OpenList())
          return false;

        // Now output the source contribs tallied to src file/line.
        SourceContribMap::const_iterator source_it = source_contribs.begin();
        for (; source_it != source_contribs.end(); ++source_it) {
          DCHECK(
              source_file_ids.find(source_it->first) != source_file_ids.end());

          if (!writer->OutputInteger(source_file_ids[source_it->first]))
            return false;

          if (!writer->OpenList())
            return false;

          const LineContribMap& lines = source_it->second;
          LineContribMap::const_iterator line_it = lines.begin();
          for (; line_it != lines.end(); ++line_it) {
            if (!writer->OutputInteger(line_it->first) ||
                !writer->OutputDouble(line_it->second)) {
              return false;
            }
          }

          if (!writer->CloseList())
            return false;
        }

        if (!writer->CloseList())
          return false;
      }

      if (!writer->CloseDict())
        return false;
    }

    if (!writer->CloseDict())
      return false;
  }

  if (!writer->CloseDict())
    return false;

  if (!writer->CloseDict())
    return false;

  return true;
}

CodeTally::SourceFileInfo* CodeTally::FindOrCreateSourceFileInfo(
    const wchar_t* source_file) {
  DCHECK(source_file != NULL);

  SourceFileInfoMap::iterator it(source_files_.find(source_file));
  if (it == source_files_.end()) {
    it = source_files_.insert(
        std::make_pair(source_file, SourceFileInfo())).first;
    it->second.file_name = it->first.c_str();
  }

  DCHECK(it != source_files_.end());
  return &it->second;
}

CodeTally::ObjectFileInfo* CodeTally::FindOrCreateObjectFileInfo(
    const wchar_t* object_file) {
  DCHECK(object_file != NULL);

  ObjectFileInfoMap::iterator it(object_files_.find(object_file));
  if (it == object_files_.end()) {
    it = object_files_.insert(
        std::make_pair(object_file, ObjectFileInfo())).first;
    it->second.file_name = it->first.c_str();
  }

  DCHECK(it != object_files_.end());
  return &it->second;
}

void CodeTally::UseRange(size_t start, size_t len) {
  if (use_counts_.size() < start + len)
    use_counts_.resize(start + len, 0);

  for (size_t i = 0; i < len; ++i)
    ++use_counts_[start + i];
}

double CodeTally::CalculateByteContribution(size_t start, size_t len) {
  DCHECK_LE(start + len, use_counts_.size());
  double sum = 0.0;
  while (len != 0) {
    sum += 1.0 / use_counts_[start];
    ++start;
    --len;
  }
  return sum;
}

bool CodeTally::OnCompilandPassOne(IDiaSymbol* compiland) {
  DCHECK(pe::IsSymTag(compiland, SymTagCompiland));

  base::win::ScopedBstr compiland_name;
  HRESULT hr = compiland->get_name(compiland_name.Receive());

  // On the first pass, we simply crawl the source lines in this compiland
  // and update the share counts for each referenced byte.
  pe::LineVisitor visitor(session_, compiland);
  return visitor.VisitLines(
      base::Bind(&CodeTally::OnLinePassOne, base::Unretained(this)));
}

bool CodeTally::OnCompilandPassTwo(IDiaSymbol* compiland) {
  DCHECK(compiland != NULL);

  base::win::ScopedBstr compiland_name;
  HRESULT hr = compiland->get_name(compiland_name.Receive());
  ObjectFileInfo* object_file =
      FindOrCreateObjectFileInfo(common::ToString(compiland_name));

  pe::ChildVisitor function_visitor(compiland, SymTagFunction);
  if (!function_visitor.VisitChildren(
          base::Bind(&CodeTally::OnFunction,
                     base::Unretained(this),
                     object_file))) {
    return false;
  }

  // On the second pass we know the share count for each byte in the executable,
  // so we can calculate accurate code contributions by line.
  pe::LineVisitor line_visitor(session_, compiland);

  return line_visitor.VisitLines(
      base::Bind(&CodeTally::OnLinePassTwo,
                 base::Unretained(this),
                 object_file));
}

bool CodeTally::OnLinePassOne(IDiaLineNumber* line_number) {
  DCHECK(line_number != NULL);

  DWORD rva = 0;
  HRESULT hr = line_number->get_relativeVirtualAddress(&rva);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get line number RVA: " << common::LogHr(hr);
    return false;
  }
  DWORD length = 0;
  hr = line_number->get_length(&length);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get line number length: " << common::LogHr(hr);
    return false;
  }

  // Account for the code usage.
  UseRange(rva, length);

  return true;
}

bool CodeTally::OnFunction(ObjectFileInfo* object_file, IDiaSymbol* function) {
  DCHECK(object_file != NULL);
  DCHECK(function != NULL);

  DWORD rva = 0;
  HRESULT hr = function->get_relativeVirtualAddress(&rva);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get function RVA: " << common::LogHr(hr);
    return false;
  }

  ULONGLONG length = 0;
  hr = function->get_length(&length);
  if (hr != S_OK || length > MAXINT) {
    LOG(ERROR) << "Failed to get function length: " << common::LogHr(hr);
    return false;
  }

  base::win::ScopedBstr name;
  hr = function->get_name(name.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get function name: " << common::LogHr(hr);
    return false;
  }

  FunctionRange range(rva, static_cast<size_t>(length));
  if (!object_file->functions.Insert(range,
                                     FunctionInfo(common::ToString(name)))) {
    FunctionInfoAddressSpace::iterator it =
        object_file->functions.FindContaining(range);
    if (it == object_file->functions.end()) {
      LOG(ERROR) << "Overlapping function info for '"
                 << common::ToString(name) << "'";
      return false;
    } else if (it->first != range) {
      LOG(ERROR) << "Function '"
                 << common::ToString(name) << "' partially overlaps function '"
                 << it->second.name << "' in object file '"
                 << object_file->file_name << "'";
      return false;
    } else {
      // If two or more functions inside an object file are folded, we'll
      // accrue and report the code contribution to only one of the instances.
      // TODO(siggi): In the case of e.g. template instantiations, this will
      //    incorrectly attribute all the contribution to one of the
      //    instantiations, which skews the tally a bit. Maybe better is to
      //    maintain a per-function size, keep all the function names around
      //    and report the contribution for each distinct function as 1/Nth of
      //    the total sum of contributions.
      LOG(INFO) << "Overlapping functions '"
                << common::ToString(name) << "' and '"
                << it->second.name << "' in object file '"
                << object_file->file_name << "'";
    }
  }

  return true;
}

bool CodeTally::OnLinePassTwo(ObjectFileInfo* object_file,
                              IDiaLineNumber* line_number) {
  DCHECK(object_file != NULL);
  DCHECK(line_number != NULL);

  DWORD rva = 0;
  HRESULT hr = line_number->get_relativeVirtualAddress(&rva);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get RVA for line: " << common::LogHr(hr);
    return false;
  }

  DWORD length = 0;
  hr = line_number->get_length(&length);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get length for line: " << common::LogHr(hr);
    return false;
  }

  base::win::ScopedComPtr<IDiaSourceFile> source_file;
  hr = line_number->get_sourceFile(source_file.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get source file for line: " << common::LogHr(hr);
    return false;
  }

  base::win::ScopedBstr source_name;
  hr = source_file->get_fileName(source_name.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get source file name for line: "
               << common::LogHr(hr);
    return false;
  }

  DWORD line = 0;
  hr = line_number->get_lineNumber(&line);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get line number: " << common::LogHr(hr);
    return false;
  }

  FunctionRange line_range(rva, length ? length : 1);
  FunctionInfoAddressSpace::iterator it =
      object_file->functions.FindContaining(line_range);
  if (it == object_file->functions.end()) {
    LOG(ERROR) << "Line info outside function in object file '"
               << object_file->file_name << "' source file '"
               << common::ToString(source_name) << "' at line: " << line;
    return true;
  }

  FunctionInfo::LineData line_data = {};

  line_data.source_file =
      FindOrCreateSourceFileInfo(common::ToString(source_name));
  DCHECK(line_data.source_file != NULL);

  line_data.offset = rva - it->first.start();
  line_data.line = line;
  line_data.code_bytes = CalculateByteContribution(rva, length);

  FunctionInfo& function_info = it->second;
  function_info.line_info.push_back(line_data);

  return true;
}
