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
// of object code contributed to an executable by source line.

#include <dia2.h>
#include <cstdio>
#include <map>
#include <vector>

#include "base/callback.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/win/scoped_com_initializer.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "sawbuck/common/com_utils.h"

// A worker class that makes it easy to visit each source line record
// in a given DIA session.
class LineVisitor {
 public:
  explicit LineVisitor(IDiaSession* session)
      : session_(session), callback_(NULL) {
    DCHECK(session != NULL);
  }

  typedef base::Callback<void(const wchar_t* object_file,
                              const wchar_t* source_file,
                              size_t line,
                              size_t rva,
                              size_t length)> VisitLineCallback;

  // Visits all lines, calling @p callback for each line.
  // @returns true on success.
  bool VisitAllLines(const VisitLineCallback& callback) {
    DCHECK(callback_ == NULL);

    callback_ = &callback;
    bool ret = VisitAllLinesImpl();
    callback_ = NULL;

    return ret;
  }

 private:
  bool EnumerateCompilandSource(IDiaSymbol* compiland,
                                IDiaSourceFile* source_file) {
    DCHECK(compiland != NULL);
    DCHECK(source_file != NULL);

    base::win::ScopedBstr compiland_name;
    HRESULT hr = compiland->get_name(compiland_name.Receive());

    base::win::ScopedBstr source_name;
    hr = source_file->get_fileName(source_name.Receive());

    base::win::ScopedComPtr<IDiaEnumLineNumbers> line_numbers;
    hr = session_->findLines(compiland, source_file, line_numbers.Receive());
    if (FAILED(hr)) {
      // This seems to happen for the occasional header file.
      return true;
    }

    while (true) {
      base::win::ScopedComPtr<IDiaLineNumber> line_number;
      ULONG fetched = 0;
      hr = line_numbers->Next(1, line_number.Receive(), &fetched);
      if (FAILED(hr)) {
        DCHECK_EQ(0U, fetched);
        DCHECK(line_number == NULL);
        LOG(ERROR) << "Unable to iterate line numbers: " << com::LogHr(hr);
        return false;
      }
      if (hr == S_FALSE)
        break;

      DCHECK_EQ(1U, fetched);
      DCHECK(line_number != NULL);

      DWORD line = 0;
      hr = line_number->get_lineNumber(&line);
      DWORD rva = 0;
      hr = line_number->get_relativeVirtualAddress(&rva);
      DWORD length = 0;
      hr = line_number->get_length(&length);

      VisitSourceLine(com::ToString(compiland_name),
                      com::ToString(source_name), line,
                      rva, length);
    }

    return true;
  }

  bool EnumerateCompilandSources(IDiaSymbol* compiland,
                                 IDiaEnumSourceFiles* source_files) {
    DCHECK(compiland != NULL);
    DCHECK(source_files != NULL);

    while (true) {
      base::win::ScopedComPtr<IDiaSourceFile> source_file;
      ULONG fetched = 0;
      HRESULT hr = source_files->Next(1, source_file.Receive(), &fetched);
      if (FAILED(hr)) {
        DCHECK_EQ(0U, fetched);
        DCHECK(source_file == NULL);
        LOG(ERROR) << "Unable to iterate source files: " << com::LogHr(hr);
        return false;
      }
      if (hr == S_FALSE)
        break;

      DCHECK_EQ(1U, fetched);
      DCHECK(compiland != NULL);

      if (!EnumerateCompilandSource(compiland, source_file))
        return false;
    }

    return true;
  }

  bool EnumerateCompilands(IDiaEnumSymbols* compilands) {
    DCHECK(compilands != NULL);

    while (true) {
      base::win::ScopedComPtr<IDiaSymbol> compiland;
      ULONG fetched = 0;
      HRESULT hr = compilands->Next(1, compiland.Receive(), &fetched);
      if (FAILED(hr)) {
        DCHECK_EQ(0U, fetched);
        DCHECK(compiland == NULL);
        LOG(ERROR) << "Unable to iterate compilands: " << com::LogHr(hr);
        return false;
      }
      if (hr == S_FALSE)
        break;

      DCHECK_EQ(1U, fetched);
      DCHECK(compiland != NULL);

      // Enumerate all source files referenced by this compiland.
      base::win::ScopedComPtr<IDiaEnumSourceFiles> source_files;
      hr = session_->findFile(compiland.get(),
                              NULL,
                              nsNone,
                              source_files.Receive());
      if (FAILED(hr)) {
        LOG(ERROR) << "Unable to get source files: " << com::LogHr(hr);
        return false;
      }

      if (!EnumerateCompilandSources(compiland, source_files))
        return false;
    }

    return true;
  }

  bool VisitAllLinesImpl() {
    DCHECK(callback_ != NULL);

    base::win::ScopedComPtr<IDiaSymbol> global;
    HRESULT hr = session_->get_globalScope(global.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Unable to get global scope: " << com::LogHr(hr);
      return false;
    }

    // Retrieve an enumerator for all compilands in this PDB.
    base::win::ScopedComPtr<IDiaEnumSymbols> compilands;
    hr = global->findChildren(SymTagCompiland,
                              NULL,
                              nsNone,
                              compilands.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Unable to get compilands: " << com::LogHr(hr);
      return false;
    }

    return EnumerateCompilands(compilands);
  }

  void VisitSourceLine(const wchar_t* object_file,
                       const wchar_t* source_file,
                       size_t line,
                       size_t rva, size_t length) {
    DCHECK(object_file != NULL);
    DCHECK(source_file != NULL);
    DCHECK(callback_ != NULL);

    callback_->Run(object_file, source_file, line, rva, length);
  }

  base::win::ScopedComPtr<IDiaSession> session_;
  const VisitLineCallback* callback_;
};

// A worker class that tallies the code generated by each source line.
class CodeTally {
 public:
  bool TallyLines(const wchar_t* pdb_file) {
    base::win::ScopedComPtr<IDiaDataSource> data_source;

    HRESULT hr = data_source.CreateInstance(CLSID_DiaSource);
    if (FAILED(hr)) {
      LOG(ERROR) << "Unable to create DIA source: " << com::LogHr(hr);
      return false;
    }
    hr = data_source->loadDataFromPdb(pdb_file);
    if (FAILED(hr)) {
      LOG(ERROR) << "Unable to load PDB: " << com::LogHr(hr);
      return false;
    }

    base::win::ScopedComPtr<IDiaSession> session;
    hr = data_source->openSession(session.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Unable to open session: " << com::LogHr(hr);
      return false;
    }

    // The output we want to generate is:
    // - Per source line in a source file, how many bytes does it generate
    //   globally.
    // - Per object file, which source files contribute to it, and how much.
    //
    // This is complicated by code sharing, which means to do an accurate tally,
    // we have to account for fractional bytes. As a case in point, a template
    // function may expand to identical code for multiple types, but the linker
    // will then fold all the identical template expansions to a single,
    // canonical function.
    // We therefore have to iterate through the source lines twice:
    // - On the first pass we update the use counts and populate the source
    //   and object file maps.
    // - On the second pass we know how often each code byte is shared, and so
    //   we can accrue the correct tally in line_code and source_contributions.
    LineVisitor visitor(session);
    if (!visitor.VisitAllLines(base::Bind(&CodeTally::PassOneVisit,
                                          base::Unretained(this)))) {
      return false;
    }
    if (!visitor.VisitAllLines(base::Bind(&CodeTally::PassTwoVisit,
                                          base::Unretained(this)))) {
      return false;
    }

    return true;
  }

  void GenerateOutput() {
    printf("events: Occurrences CodeSize\n\n");

    SourceFileMap::const_iterator src_it(source_files_.begin());
    for (; src_it != source_files_.end(); ++src_it) {
      const SourceFile& src = src_it->second;

      // Reverse backslashes for output.
      std::wstring file_name = src.file_name;
      ReplaceChars(file_name, L"\\", L"/", &file_name);
      printf("fl=%ls\n", file_name.c_str());
      printf("fn=ALL\n");
      for (size_t line = 1; line < src.line_code.size(); ++line) {
        const LineInfo& info = src.line_code[line];
        if (info.code_bytes != 0.0) {
          printf("%d %d %f\n", line, info.occurrences, info.code_bytes);
        }
      }
    }

    // TODO(siggi): Figure out some way of representing contributions
    //    per source/object file.
#if 0
    ObjectFileMap::const_iterator obj_it(object_files_.begin());
    for (; obj_it != object_files_.end(); ++obj_it) {
      const ObjectFile& obj = obj_it->second;

      printf("ob=%ls\n", obj.file_name);
      printf("fn=ignore\n");
      const SourceContributionMap& cont = obj.source_contributions;
      SourceContributionMap::const_iterator cont_it(cont.begin());
      for (; cont_it != cont.end(); ++cont_it) {
        double code = cont_it->second;
        if (code != 0.0) {
          printf("cfl=%ws\n", cont_it->first->file_name);
          printf("cfn=ignore\n");
          printf("calls=1 1\n");
          printf("1 0 0.0 %f\n", code);
        }
      }
    }
#endif
  }

 private:
  // Data we maintain per source line.
  struct LineInfo {
    // The number of times we encountered this line.
    size_t occurrences;
    // The total number of code bytes accrued to this line.
    double code_bytes;
  };

  // The data maintained per source file.
  struct SourceFile {
    SourceFile() : file_name(NULL) {
    }

    // This source file's name.
    const wchar_t* file_name;

    // The amount of code attributed to each line of this file.
    std::vector<LineInfo> line_code;
  };

  // The data maintained per object file.
  typedef std::map<SourceFile*, double> SourceContributionMap;
  struct ObjectFile {
    ObjectFile() : file_name(NULL) {
    }

    // This object file's name.
    const wchar_t* file_name;

    // Maps from source file to the sum of that file's code
    // contribution to this object file.
    SourceContributionMap source_contributions;
  };
  typedef std::map<std::wstring, SourceFile> SourceFileMap;
  typedef std::map<std::wstring, ObjectFile> ObjectFileMap;

  SourceFile* FindOrCreateSourceFile(const wchar_t* source_file) {
    DCHECK(source_file != NULL);

    SourceFileMap::iterator it(source_files_.find(source_file));
    if (it == source_files_.end()) {
      it = source_files_.insert(
          std::make_pair(source_file, SourceFile())).first;
      it->second.file_name = it->first.c_str();
    }

    DCHECK(it != source_files_.end());
    return &it->second;
  }

  ObjectFile* FindOrCreateObjectFile(const wchar_t* object_file) {
    DCHECK(object_file != NULL);

    ObjectFileMap::iterator it(object_files_.find(object_file));
    if (it == object_files_.end()) {
      it = object_files_.insert(
          std::make_pair(object_file, ObjectFile())).first;
      it->second.file_name = it->first.c_str();
    }

    DCHECK(it != object_files_.end());
    return &it->second;
  }

  void UseRange(size_t start, size_t len) {
    if (use_counts_.size() < start + len)
      use_counts_.resize(start + len, 0);

    for (size_t i = 0; i < len; ++i)
      ++use_counts_[start + i];
  }

  // The first pass updates all use counts and instantiates
  // each source and object file.
  void PassOneVisit(const wchar_t* object_file_name,
                    const wchar_t* source_file_name,
                    size_t line,
                    size_t rva,
                    size_t length) {
    DCHECK(object_file_name != NULL);
    DCHECK(source_file_name != NULL);

    // Account for the code usage.
    UseRange(rva, length);

    // Instantiate the source and object files.
    SourceFile* source_file = FindOrCreateSourceFile(source_file_name);
    DCHECK(source_file != NULL);

    ObjectFile* object_file = FindOrCreateObjectFile(object_file_name);
    DCHECK(object_file != NULL);

    // And note that the source file occurs in this object.
    object_file->source_contributions[source_file] = 0.0;
  }

  // The second pass can accurately tally code contribution as
  // the first pass has calculated the sharing (use) count of
  // each byte in the binary.
  void PassTwoVisit(const wchar_t* object_file_name,
                    const wchar_t* source_file_name,
                    size_t line,
                    size_t rva,
                    size_t length) {
    DCHECK(object_file_name != NULL);
    DCHECK(source_file_name != NULL);

    // Get the source and object files.
    SourceFile& source_file = source_files_[source_file_name];
    ObjectFile& object_file = object_files_[object_file_name];

    DCHECK(source_file.file_name != NULL);
    DCHECK_EQ(0, wcscmp(source_file_name, source_file.file_name));
    DCHECK(object_file.file_name != NULL);
    DCHECK_EQ(0, wcscmp(object_file_name, object_file.file_name));
    DCHECK_LE(rva + length, use_counts_.size());

    // Sum up the code contribution for this line.
    double code_sum = 0.0;
    for (size_t i = 0; i < length; ++i) {
      DCHECK_LE(1U, use_counts_[rva + i]);
      code_sum += 1.0 / use_counts_[rva + i];
    }

    // Add the code contribution to each source line.
    if (source_file.line_code.size() < line + 1) {
      const LineInfo kNullInfo = {};
      source_file.line_code.resize(line + 1, kNullInfo);
    }
    // Update the code contribution for the source line and for the
    // source file in that object.
    source_file.line_code[line].occurrences += 1;
    source_file.line_code[line].code_bytes += code_sum;
    object_file.source_contributions[&source_file] += code_sum;
  }

  // Maps from source file name to SourceFile.
  SourceFileMap source_files_;

  // Maps from object file name to ObjectFile.
  ObjectFileMap object_files_;

  // Keeps track of how many times each byte in Chrome.dll was referenced from
  // any source line.
  std::vector<size_t> use_counts_;
};

int wmain(int argc, wchar_t* argv[]) {
  base::win::ScopedCOMInitializer com_initializer;

  if (argc != 2) {
    fprintf(stderr, "Usage: %ws <pdb_file>\n", argv[0]);
    return 1;
  }

  CodeTally tally;
  if (!tally.TallyLines(argv[1]))
    return 0;

  tally.GenerateOutput();

  return 1;
}
