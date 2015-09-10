Copyright 2015 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# PDB type info stream description

This file describes the observed usage of PDB references as produced by Visual
C++ 2013. Each PDB record which contains reference to a different record is
described in the following format.


##### *Record name*
- *field name:* *Set of possible types referenced by this field*
- *second field name:* *Set of possible types referenced by this field*

## Records in the type info stream with reference fields

##### Array
- *elemtype:* OptionallyModifiedType
- *idxtype:* IndexingType

##### ArglistRecord
- *index:* OptionallyModifiedType

##### BClass
- *index:* Class

##### Bitfield
 - *type:* IntegralBasicType |
           Enum

##### Class
 - *field:* FieldList
 - *derived:* Type  (not used by VS 2013)
 - *vshape:* VShape

##### Enum
 - *field:* Fieldlist
 - *utype:* IntegralBasicType

##### Fieldlist
 This record is concatenation of records of the following types:

 - BCLass
 - VBClass
 - Enumerate
 - FriendCls
 - FriendFcn
 - Index
 - Member
 - STMember
 - Method
 - NestType
 - VFuncTab
 - OneMethod
 - VFuncOff

##### FriendCls (not used by VS 2013)
 - *index:* UserDefinedType

##### FriendFcn (not used by VS 2013)
 - *index:* Procedure

##### Index
 - *index:* Fieldlist

##### Member
- *index:* OptionallyModifiedType |
           Bitfield

##### Method
- *mlist:* MethodList

##### Methodlist
 This record is just concatenation of MethodListRecord types.

##### MethodListRecord
- *index:* MFunction

##### MFunction
- *rvtype:* OptionallyModifiedType
- *classtype:* StructuredType
- *thistype:* Pointer (to the classtype structure)
- *arglist:* Arglist

##### Modifier
- *type:* ModifiableType

##### NestType
- *index:* UserDefinedType

##### OneMethod
- *index:* MFunction

##### Pointer
- *utype:* PointableType
- *containing_class:* StructuredType (optional field)

##### Procedure
- *rvtype:* OptionallyModifiedType
- *arglist:* Arglist

##### STMember
- *index:* OptionallyModifiedType

##### Union
- *field:* Fieldlist

##### VBClass
- *index:* Class

##### VFuncTab
- *index:* Pointer (which points to VTShape)


## Sets of types used above

- IndexingType
  - uint32_t
  - uint64_t
- IntegralBasicType
  - all signed and unsigned integer types.
- BasicType
  - type index smaller than 0x1000.
- StructuredType
  - Class
  - Union
- UserDefinedType
 - StructuredType
 - Enum
- ModifiableType
  - BasicType
  - UserDefinedType
- OptionallyModifiedType
 - ModifiableType
 - Modifier
 - Pointer
 - Array
- PointableType
  - OptionallyModifiedType
  - Procedure
  - MFunction
  - VTShape
