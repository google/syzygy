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

#include "syzygy/refinery/types/pdb_crawler.h"

#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_type_info_stream_enum.h"
#include "syzygy/pe/cvinfo_ext.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

// Declaration of struct used for the unknown records. This is needed because
// the macro LEAF_CASE_TABLE in ParseType generates call to Reader<UnknownLeaf>
// in some cases. But the CVInfo.h header has no declaration of this struct
// which would prevent the compilation.
namespace Microsoft_Cci_Pdb {
struct UnknownLeaf;
}

namespace refinery {

namespace {

namespace cci = Microsoft_Cci_Pdb;

struct TempType {
  TempType(const base::string16& n,
           const base::string16& dn,
           TypeId t,
           Type::Flags f)
      : name(n), decorated_name(dn), type_id(t), flags(f) {}

  bool is_const() const { return (flags & Type::FLAG_CONST) != 0; }
  bool is_volatile() const { return (flags & Type::FLAG_VOLATILE) != 0; }

  // CV flags.
  Type::Flags flags;

  // Name of the type.
  base::string16 name;

  // Decorated name of the type.
  base::string16 decorated_name;

  // Type Id of the closest element on the way down in the type repository.
  TypeId type_id;
};

class TypeCreator {
 public:
  explicit TypeCreator(TypeRepository* repository);
  ~TypeCreator();

  // Crawls @p stream, creates all types and assigns names to pointers.
  bool CreateTypes(scoped_refptr<pdb::PdbStream> stream);

 private:
  // Parses current type info record given its type.
  // @param type_creator pointer to the TypeCreator object which called this
  //   function.
  // @returns true on success, false on failure.
  template <typename T>
  bool ReadType() {
    return true;
  }

  // Parses type given by a type from the PDB type info stream.
  // @returns true on success, false on failure.
  bool ParseType(uint16_t type);

  // Checks if type object referenced by @p type_index exists.
  // @returns pointer to the type object.
  TempType* FindOrCreateTempType(TypeId type_index);

  // Creates a basic type object given its @p type_index (when needed).
  // @returns pointer to the type object.
  TempType* CreateBasicType(TypeId type_index);

  // Adds temporary type to the temporary hash.
  TempType* AddTempType(TypeId type_index,
                        const base::string16& name,
                        const base::string16& decorated_name,
                        TypeId type_id,
                        Type::Flags flags);

  // @returns name for a basic type specified by its @ type.
  static base::string16 BasicTypeName(uint32 type);

  // @returns size for a basic type specified by its @ type.
  static size_t BasicTypeSize(uint32 type);

  // @returns the string of CV modifiers.
  static base::string16 GetCVMod(Type::Flags flags);

  // @returns the CV_prmode of the given basic type index.
  static cci::CV_prmode TypeIndexToPrMode(TypeId type_index);

  // Pointer to a type info repository.
  TypeRepository* repository_;

  // Type info enumerator used to transverse the stream.
  pdb::TypeInfoEnumerator type_info_enum_;

  // Temporary types hash.
  base::hash_map<TypeId, TempType*> temp_stash_;
};

// Parses pointers from the type info stream.
template <>
bool TypeCreator::ReadType<cci::LeafPointer>() {
  cci::LeafPointer::LeafPointerBody type_info = {};
  if (!type_info_enum_.GetDataStream()->Read(&type_info, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  size_t size;
  Type::Flags flags = 0x0000;

  switch (type_info.attr & cci::ptrtype) {
    case cci::CV_PTR_NEAR32:
      size = 4;
      break;
    case cci::CV_PTR_64:
      size = 8;
      break;
    default:
      // TODO(mopler): What are the other pointer types and their sizes?
      size = 0;
      break;
  }

  // Try to find the object in the repository.
  TempType* child = FindOrCreateTempType(type_info.utype);
  if (child == nullptr)
    return false;

  base::string16 name = child->name + L"*";
  base::string16 decorated_name = child->decorated_name + L"*";
  TypeId type_id = type_info_enum_.type_id();

  if (type_info.attr & cci::isconst)
    flags |= Type::FLAG_CONST;
  if (type_info.attr & cci::isvolatile)
    flags |= Type::FLAG_VOLATILE;

  name += GetCVMod(flags);
  decorated_name += GetCVMod(flags);

  PointerTypePtr created = new PointerType(size);

  // Setting the flags from the child node - this is needed because of
  // different semantics between PDB file and Type interface. In PDB pointer
  // has a const flag when it's const, while here pointer has a const flag if
  // it points to a const type.
  created->Finalize(child->flags, child->type_id);
  created->SetName(child->name + L"*");

  repository_->AddTypeWithId(created, type_id);

  // Add to temporary stash
  AddTempType(type_info_enum_.type_id(), name, decorated_name, type_id, flags);
  return true;
}

// Parses modifiers from the type info stream.
template <>
bool TypeCreator::ReadType<cci::LeafModifier>() {
  cci::LeafModifier type_info = {};
  LeafModifierAttribute modifier_attributes = {};
  size_t to_read = offsetof(cci::LeafModifier, attr);
  size_t bytes_read = 0;

  scoped_refptr<pdb::PdbStream> stream = type_info_enum_.GetDataStream();
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      !stream->Read(&modifier_attributes, 1) || bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }

  Type::Flags flags = 0x0000;
  TempType* child = FindOrCreateTempType(type_info.type);

  if (child == nullptr)
    return false;

  if (modifier_attributes.mod_const)
    flags |= Type::FLAG_CONST;
  if (modifier_attributes.mod_volatile)
    flags |= Type::FLAG_VOLATILE;

  AddTempType(type_info_enum_.type_id(), child->name + GetCVMod(flags),
              child->decorated_name + GetCVMod(flags), child->type_id, flags);
  return true;
}

// TODO(mopler): Add template specialization for more leaves.

TypeCreator::TypeCreator(TypeRepository* repository) : repository_(repository) {
  DCHECK(repository);
}

TypeCreator::~TypeCreator() {
  for (auto it = temp_stash_.begin(); it != temp_stash_.end(); ++it)
    delete it->second;
}

base::string16 TypeCreator::BasicTypeName(uint32 type) {
  // TODO(mopler): better naming of the basic types.
  switch (type) {
// Just return the name of the enum.
#define SPECIAL_TYPE_NAME(record_type) \
  case cci::record_type: {             \
    return L#record_type;              \
  }
    SPECIAL_TYPE_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
    default:
      return L"unknown_basic_type";
  }
}

size_t TypeCreator::BasicTypeSize(uint32 type) {
  // TODO(mopler): this needs to implemented ASAP.
  return 0;
}

base::string16 TypeCreator::GetCVMod(Type::Flags flags) {
  base::string16 suffix;
  if (flags & Type::FLAG_CONST) {
    suffix += L" const";
  }
  if (flags & Type::FLAG_VOLATILE) {
    flags |= Type::FLAG_VOLATILE;
    suffix += L" volatile";
  }
  return suffix;
}

TempType* TypeCreator::AddTempType(TypeId type_index,
                                   const base::string16& name,
                                   const base::string16& decorated_name,
                                   TypeId type_id,
                                   Type::Flags flags) {
  TempType* temp_pointer = new TempType(name, decorated_name, type_id, flags);
  bool inserted =
      temp_stash_.insert(std::make_pair(type_index, temp_pointer)).second;
  DCHECK(inserted);

  return temp_pointer;
}

cci::CV_prmode TypeCreator::TypeIndexToPrMode(TypeId type_index) {
  return static_cast<cci::CV_prmode>(
      (type_index & cci::CV_PRIMITIVE_TYPE::CV_MMASK) >>
      cci::CV_PRIMITIVE_TYPE::CV_MSHIFT);
}

TempType* TypeCreator::CreateBasicType(TypeId type_index) {
  // Check if we are dealing with pointer.
  cci::CV_prmode prmode = TypeIndexToPrMode(type_index);
  if (prmode == cci::CV_TM_DIRECT) {
    // Create and add type to the repository.
    BasicTypePtr created =
        new BasicType(BasicTypeName(type_index), BasicTypeSize(type_index));
    bool inserted = repository_->AddTypeWithId(created, type_index);
    DCHECK(inserted);

    // Create temporary type to temporary stash.
    return AddTempType(type_index, BasicTypeName(type_index),
                       BasicTypeName(type_index), type_index,
                       BasicTypeSize(type_index));
  } else {
    TypeId basic_index = type_index & (cci::CV_PRIMITIVE_TYPE::CV_TMASK |
                                       cci::CV_PRIMITIVE_TYPE::CV_SMASK);
    TempType* child = FindOrCreateTempType(basic_index);
    if (child == nullptr)
      return false;

    // Get pointer size.
    size_t size = 0;
    switch (prmode) {
      case cci::CV_TM_NPTR32:
        size = 4;
        break;
      case cci::CV_TM_NPTR64:
        size = 8;
        break;
      case cci::CV_TM_NPTR128:
        size = 16;
        break;
      default:
        return nullptr;
    }

    // Create and add type to the repository.
    PointerTypePtr created = new PointerType(size);
    created->Finalize(0x0, basic_index);
    created->SetName(child->name + L"*");
    bool inserted = repository_->AddTypeWithId(created, type_index);
    DCHECK(inserted);

    // Create temporary type to temporary stash.
    return AddTempType(type_index, child->name + L"*",
                       child->decorated_name + L"*", type_index, 0);
  }
}

TempType* TypeCreator::FindOrCreateTempType(TypeId type_index) {
  auto it = temp_stash_.find(type_index);
  if (it != temp_stash_.end())
    return it->second;

  // Check if it is a special type index.
  if (type_index >= type_info_enum_.type_info_header().type_min) {
    // For now returning wildcard dummy.
    // TODO(mopler): return nullptr here once we implement the other types.
    return AddTempType(type_index, L"dummy", L"dummy", type_index, 0);
  } else {
    // Construct the needed basic type.
    return CreateBasicType(type_index);
  }
}

bool TypeCreator::ParseType(uint16_t type) {
  switch (type) {
// Call the template reader to process the current record.
#define LEAF_TYPE_DUMP(type_value, struct_type) \
  case cci::type_value:                         \
    return ReadType<cci::##struct_type>();
    LEAF_CASE_TABLE(LEAF_TYPE_DUMP)
#undef LEAF_TYPE_DUMP
    default:
      return false;
  }
}

bool TypeCreator::CreateTypes(scoped_refptr<pdb::PdbStream> stream) {
  DCHECK(stream);

  if (!type_info_enum_.Init(stream.get())) {
    LOG(ERROR) << "Unable to initialize type info stream enumerator.";
    return false;
  }

  const TypeId kSmallestUnreservedIndex = 0x1000;
  if (type_info_enum_.type_info_header().type_min < kSmallestUnreservedIndex) {
    LOG(ERROR) << "Degenerate stream with type indices in the reserved range.";
    return false;
  }

  while (!type_info_enum_.EndOfStream()) {
    if (!type_info_enum_.NextTypeInfoRecord()) {
      LOG(ERROR) << "Unable to load next type info record.";
      return false;
    }

    if (!ParseType(type_info_enum_.type())) {
      LOG(ERROR) << "Unable to parse type info stream.";
      return false;
    }
  }

  return true;
}

}  // namespace

PdbCrawler::PdbCrawler() {
}

PdbCrawler::~PdbCrawler() {
}

bool PdbCrawler::InitializeForFile(const base::FilePath& path) {
  pdb::PdbReader reader;
  pdb::PdbFile pdb_file;

  if (!reader.Read(path, &pdb_file)) {
    LOG(ERROR) << "Failed to read PDB file " << path.value() << ".";
    return false;
  }

  stream_ = pdb_file.GetStream(pdb::kTpiStream);
  return true;
}

bool PdbCrawler::GetTypes(TypeRepository* types) {
  DCHECK(types);
  DCHECK(stream_);

  TypeCreator creator(types);

  return creator.CreateTypes(stream_);
}

}  // namespace refinery
