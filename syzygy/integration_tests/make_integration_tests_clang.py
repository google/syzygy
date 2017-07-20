#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A script to compile the integration tests with llvm's clang,
instrument the code with llvm's Asan, and link it to the syzyasan_rtl
runtime environment.
"""

import optparse
import os
import re
import subprocess
import sys


_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
_SRC_DIR = os.path.abspath(os.path.join(_SCRIPT_DIR, os.pardir, os.pardir))
_CLANG_CL_PATH = os.path.join(_SRC_DIR,
    'third_party', 'llvm-build', 'Release+Asserts', 'bin', 'clang-cl.exe')


def compile_with_asan(clang_path, source_files, src_dir, object_files,
                      target_name):
  """Compiles the files and instruments them with LLVM's ASAN.
  The linking is done with the method link below.

  Only compiles the files and instruments them with LLVM's Asan but does not
  link them. The linking is done separately in the method link.

  Args:
    clang_path: Path to the clang-cl compiler.
    source_files: The source files to be compiled.
    src_dir: The repository where the syzygy src is located.
    object_files: The path where each object file should be generated.
    target_name: The name of the target being build.
  """

  compiler_flags = [
      '-c',
      '-m32',
      '-fsanitize=address',
      '-mllvm',
      '-asan-instrumentation-with-call-threshold=0',
      '-mllvm',
      '-asan-stack=0',
      '-DUNICODE',
      '-D_UNICODE',
      '-DNOMINMAX',
      '-D_CRT_SECURE_NO_WARNINGS',
      '/Zi',
      '-I',
      src_dir,
  ]

  compile_command_base = [clang_path]
  compile_command_base.extend(compiler_flags)

  for source_file, object_file in zip(source_files, object_files):
    compile_command = list(compile_command_base)
    compile_command.extend([source_file, '-o', object_file])
    ret = subprocess.call(compile_command)
    if ret != 0:
      print 'ERROR: Failed compiling %s using clang-cl.' % target_name
      return ret
  return ret


def link(clang_path, object_files, build_dir, target_name, def_file):
  """ Links the object files and produces the integration_tests_clang_dll.dll.

  Links the object files and produces the dll. The object files have to be
  produced by the compile method above.

  Args:
    clang_path: Path to the clang-cl compiler in the syzygy project.
    source_files: The source file names which are converted to obj filenames.
    build_dir: The directory where to produce the linked dll.
    target_name: The name of the target being build.
  """

  linker_flags = [
      '-o',
      os.path.join(build_dir, target_name + '.dll'),
      '/link',
      '/dll',
      os.path.join(build_dir, 'export_dll.dll.lib'),
      os.path.join(build_dir, 'syzyasan_rtl.dll.lib'),
      '-defaultlib:libcmt',
      '/debug',
      '/def:' + def_file,
  ]

  linker_command = [clang_path, '-m32']
  linker_command.extend(object_files)
  linker_command.extend(linker_flags)

  ret = subprocess.call(linker_command)

  if ret != 0:
    print 'ERROR: Failed to link %s using clang-cl.' % target_name
  return ret


def main():
  parser = optparse.OptionParser(usage='%prog [options]')
  parser.add_option('--output-dir',
      help='Path to the Syzygy Release directory.')
  parser.add_option('--input-files', help='Files to be compiled and linked.')
  parser.add_option('--target-name', help='Name of the target to be compiled.')
  parser.add_option('--def-file', help='Definition file for the dll.')

  options, _ = parser.parse_args()

  if not options.output_dir:
    parser.error('--output-dir is required.')
  if not options.input_files:
    parser.error('--input-files is required.')
  if not options.target_name:
    parser.error('--target-name is required.')
  if not options.def_file:
    parser.error('--def-file is required.')

  def get_object_file_location(source_file,
                               output_dir, target_name):
    return os.path.join(output_dir, 'obj',
        os.path.dirname(os.path.relpath(source_file, _SRC_DIR)),
        '%s.%s.obj' % (target_name,
                       os.path.splitext(os.path.basename(source_file))[0]))

  source_files = options.input_files.split()
  object_files = []

  for source_file in source_files:
    object_files.append(get_object_file_location(source_file,
                                                 options.output_dir,
                                                 options.target_name))

  ret = compile_with_asan(_CLANG_CL_PATH, source_files, _SRC_DIR,
                          object_files, options.target_name)

  if ret == 0:
    ret = link(_CLANG_CL_PATH, object_files, options.output_dir,
               options.target_name, options.def_file)
  else:
    print ('ERROR: Compilation of %s failed, skipping link step.'
           % options.target_name)

  return ret


if __name__ == '__main__':
  sys.exit(main())
