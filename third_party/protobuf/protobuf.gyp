# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# GYP build configuration for protobuf library. 

{
  # These are shared across all protobuf related targets. Things that are
  # specific to library targets are defined in protobuf_common.gypi and
  # included via that.
  'target_defaults': {
    'msvs_disabled_warnings': [
      4018,  # signed/unsigned mismatch in comparison
      4065,  # switch statements contains 'default' but no 'case' labels
      # This is due to line 71 of google/protobuf/extension_set. The code
      # wants the compiler to be smarter than MSVC.
      4715,  # not all control paths return a value
    ],
    'include_dirs': [
      '.',  # For config.h.
      'src',  # For the google/ includes.
    ],
    # This macro must be defined to suppress the use of dynamic_cast<>,
    # which requires RTTI.
    'defines': [
      'GOOGLE_PROTOBUF_NO_RTTI',
      'GOOGLE_PROTOBUF_NO_STATIC_INITIALIZER',
    ],
    'defines!': [
      'WIN32_LEAN_AND_MEAN',  # Protobuf defines this itself.
    ],
  },

  'targets': [
    # The "lite" lib is about 1/7th the size of the heavy lib,
    # but it doesn't support some of the more exotic features of
    # protobufs, like reflection.  To generate C++ code that can link
    # against the lite version of the library, add the option line:
    #
    #   option optimize_for = LITE_RUNTIME;
    #
    # to your .proto file.
    {
      'target_name': 'protobuf_lite_lib',
      'type': 'static_library',
      'includes': [ 'protobuf_common.gypi', 'protobuf_lite.gypi' ],
    },
    # This is the full, heavy protobuf lib that's needed for C++ .protos
    # that don't specify the LITE_RUNTIME option. The protocol compiler itself
    # (protoc) falls into that category.
    {
      'target_name': 'protobuf_lib',
      'type': 'static_library',
      'includes': [ 'protobuf_common.gypi', 'protobuf_lite.gypi' ],
      'sources': [
        'src/google/protobuf/descriptor.cc',
        'src/google/protobuf/descriptor.h',
        'src/google/protobuf/descriptor.pb.cc',
        'src/google/protobuf/descriptor.pb.h',
        'src/google/protobuf/descriptor_database.cc',
        'src/google/protobuf/descriptor_database.h',
        'src/google/protobuf/dynamic_message.cc',
        'src/google/protobuf/dynamic_message.h',
        'src/google/protobuf/extension_set_heavy.cc',
        'src/google/protobuf/generated_enum_reflection.h',
        'src/google/protobuf/generated_message_reflection.cc',
        'src/google/protobuf/generated_message_reflection.h',
        'src/google/protobuf/message.cc',
        'src/google/protobuf/message.h',
        'src/google/protobuf/reflection_ops.cc',
        'src/google/protobuf/reflection_ops.h',
        'src/google/protobuf/service.cc',
        'src/google/protobuf/service.h',
        'src/google/protobuf/text_format.cc',
        'src/google/protobuf/text_format.h',
        'src/google/protobuf/unknown_field_set.cc',
        'src/google/protobuf/unknown_field_set.h',
        'src/google/protobuf/wire_format.cc',
        'src/google/protobuf/wire_format.h',
        'src/google/protobuf/compiler/importer.cc',
        'src/google/protobuf/compiler/importer.h',
        'src/google/protobuf/compiler/parser.cc',
        'src/google/protobuf/compiler/parser.h',
        'src/google/protobuf/io/gzip_stream.cc',
        'src/google/protobuf/io/gzip_stream.h',
        'src/google/protobuf/io/printer.cc',
        'src/google/protobuf/io/printer.h',
        'src/google/protobuf/io/strtod.cc',
        'src/google/protobuf/io/strtod.h',
        'src/google/protobuf/io/tokenizer.cc',
        'src/google/protobuf/io/tokenizer.h',
        'src/google/protobuf/io/zero_copy_stream_impl.cc',
        'src/google/protobuf/io/zero_copy_stream_impl.h',
        'src/google/protobuf/stubs/strutil.cc',
        'src/google/protobuf/stubs/strutil.h',
        'src/google/protobuf/stubs/substitute.cc',
        'src/google/protobuf/stubs/substitute.h',
        'src/google/protobuf/stubs/structurally_valid.cc',
      ],
      'dependencies': [
        '<(src)/third_party/zlib/zlib.gyp:zlib',
      ]
    },
    {
      'target_name': 'protoc_lib',
      'type': 'static_library',
      'includes': [ 'protobuf_common.gypi' ],
      'sources': [
        'src/google/protobuf/compiler/code_generator.cc',
        'src/google/protobuf/compiler/code_generator.h',
        'src/google/protobuf/compiler/command_line_interface.cc',
        'src/google/protobuf/compiler/command_line_interface.h',
        'src/google/protobuf/compiler/plugin.cc',
        'src/google/protobuf/compiler/plugin.h',
        'src/google/protobuf/compiler/plugin.pb.cc',
        'src/google/protobuf/compiler/plugin.pb.h',
        'src/google/protobuf/compiler/subprocess.cc',
        'src/google/protobuf/compiler/subprocess.h',
        'src/google/protobuf/compiler/zip_writer.cc',
        'src/google/protobuf/compiler/zip_writer.h',
        'src/google/protobuf/compiler/cpp/cpp_enum.cc',
        'src/google/protobuf/compiler/cpp/cpp_enum.h',
        'src/google/protobuf/compiler/cpp/cpp_enum_field.cc',
        'src/google/protobuf/compiler/cpp/cpp_enum_field.h',
        'src/google/protobuf/compiler/cpp/cpp_extension.cc',
        'src/google/protobuf/compiler/cpp/cpp_extension.h',
        'src/google/protobuf/compiler/cpp/cpp_field.cc',
        'src/google/protobuf/compiler/cpp/cpp_field.h',
        'src/google/protobuf/compiler/cpp/cpp_file.cc',
        'src/google/protobuf/compiler/cpp/cpp_file.h',
        'src/google/protobuf/compiler/cpp/cpp_generator.cc',
        'src/google/protobuf/compiler/cpp/cpp_helpers.cc',
        'src/google/protobuf/compiler/cpp/cpp_helpers.h',
        'src/google/protobuf/compiler/cpp/cpp_message.cc',
        'src/google/protobuf/compiler/cpp/cpp_message.h',
        'src/google/protobuf/compiler/cpp/cpp_message_field.cc',
        'src/google/protobuf/compiler/cpp/cpp_message_field.h',
        'src/google/protobuf/compiler/cpp/cpp_options.h',
        'src/google/protobuf/compiler/cpp/cpp_primitive_field.cc',
        'src/google/protobuf/compiler/cpp/cpp_primitive_field.h',
        'src/google/protobuf/compiler/cpp/cpp_service.cc',
        'src/google/protobuf/compiler/cpp/cpp_service.h',
        'src/google/protobuf/compiler/cpp/cpp_string_field.cc',
        'src/google/protobuf/compiler/cpp/cpp_string_field.h',
        'src/google/protobuf/compiler/java/java_context.cc',
        'src/google/protobuf/compiler/java/java_context.h',
        'src/google/protobuf/compiler/java/java_enum.cc',
        'src/google/protobuf/compiler/java/java_enum.h',
        'src/google/protobuf/compiler/java/java_enum_field.cc',
        'src/google/protobuf/compiler/java/java_enum_field.h',
        'src/google/protobuf/compiler/java/java_extension.cc',
        'src/google/protobuf/compiler/java/java_extension.h',
        'src/google/protobuf/compiler/java/java_field.cc',
        'src/google/protobuf/compiler/java/java_field.h',
        'src/google/protobuf/compiler/java/java_file.cc',
        'src/google/protobuf/compiler/java/java_file.h',
        'src/google/protobuf/compiler/java/java_generator.cc',
        'src/google/protobuf/compiler/java/java_generator_factory.cc',
        'src/google/protobuf/compiler/java/java_generator_factory.h',
        'src/google/protobuf/compiler/java/java_helpers.cc',
        'src/google/protobuf/compiler/java/java_helpers.h',
        'src/google/protobuf/compiler/java/java_lazy_message_field.cc',
        'src/google/protobuf/compiler/java/java_lazy_message_field.h',
        'src/google/protobuf/compiler/java/java_message.cc',
        'src/google/protobuf/compiler/java/java_message.h',
        'src/google/protobuf/compiler/java/java_message_field.cc',
        'src/google/protobuf/compiler/java/java_message_field.h',
        'src/google/protobuf/compiler/java/java_name_resolver.cc',
        'src/google/protobuf/compiler/java/java_name_resolver.h',
        'src/google/protobuf/compiler/java/java_primitive_field.cc',
        'src/google/protobuf/compiler/java/java_primitive_field.h',
        'src/google/protobuf/compiler/java/java_shared_code_generator.cc',
        'src/google/protobuf/compiler/java/java_shared_code_generator.h',
        'src/google/protobuf/compiler/java/java_service.cc',
        'src/google/protobuf/compiler/java/java_service.h',
        'src/google/protobuf/compiler/java/java_string_field.cc',
        'src/google/protobuf/compiler/java/java_string_field.h',
        'src/google/protobuf/compiler/java/java_doc_comment.cc',
        'src/google/protobuf/compiler/java/java_doc_comment.h',
        'src/google/protobuf/compiler/python/python_generator.cc',
        'src/google/protobuf/compiler/python/python_generator.h',
      ],
    },
    {
      'target_name': 'protoc',
      'type': 'executable',
      'sources': [
        'src/google/protobuf/compiler/main.cc',
      ],
      'dependencies': [
        'protobuf_lib',
        'protoc_lib',
      ],
    },
  ],
}
