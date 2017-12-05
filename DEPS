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
# Syzygy builds on Chrome base, uses GYP, GTest, all of which requires
# this build configuration.

vars = {
  "chromium_git": "https://chromium.googlesource.com/",

  # Paths to installed utilities used in hooks. These need to use
  # Windows style paths.
  "gyp_path": "src\\syzygy\\build\\gyp_main.py",

  # This is expected to be Python 2.7 from depot_tools.
  "python_path": "python"
}

deps = {
  # Chrome base and other top-level dependencies:
  "src/base":
    Var("chromium_git") + "chromium/src/base@8d8b1b54e",
  "src/build":
    Var("chromium_git") + "chromium/src/build@8158e0740",

  # Build tools:
  "src/buildtools":
    Var("chromium_git") + "chromium/buildtools@ecc8e25",

  # Testing dependencies:
  "src/testing":
    Var("chromium_git") + "chromium/src/testing@e09b76f3",
  "src/testing/gmock":
    Var("chromium_git") + "external/gmock@0421b6f",
  "src/testing/gtest":
    Var("chromium_git") + "external/gtest@86dec5c",

  # Chromium third_party dependencies:
  "src/third_party/modp_b64":
    Var("chromium_git") + "chromium/src/third_party/modp_b64@781604df",
  "src/third_party/zlib":
    Var("chromium_git") + "chromium/src/third_party/zlib@4576304",
  "src/third_party/protobuf/src":
    Var("chromium_git") + "external/github.com/google/protobuf@786379a",

  # ICU:
  "src/third_party/icu":
    Var("chromium_git") + "chromium/deps/icu.git@54f86bb",

  # A general purpose X86 disassembler.
  "src/third_party/distorm/files":
    "https://github.com/gdabah/distorm.git@25c9359",

  # Used for benchmarking.
  "src/third_party/dromaeo/files":
    Var("chromium_git") + "chromium/src/chrome/test/data/dromaeo@bdd0d52",

  # Used by our various ETW processing scripts.
  # TODO(sebmarchand): Switch to the GitHub Organisation clone of this project
  #     once its available.
  "src/third_party/sawbuck/py/etw":
    "https://github.com/sebmarchand/pyetw.git@302431b",

  # A pinned version of Python to use with our scripts.
  # TODO(chrisha): Upgrade to Python 2.7.6, like the rest of Chromium.
  "src/third_party/python_26":
    Var("chromium_git") + "chromium/deps/python_26@5bb4080",

  # This brings in GYP.
  "src/tools/gyp":
    "https://chromium.googlesource.com/external/gyp@61259d5",

  # This brings in code coverage tools, like croc. This is required for our
  # coverage generation.
  "src/tools/code_coverage":
    Var("chromium_git") + "chromium/src/tools/code_coverage@23081ea",

  # This brings in Clang. This is required to generate the project files.
  "src/tools/clang":
    Var("chromium_git") + "chromium/src/tools/clang@7474c16",

  # This brings in Crashpad, used by SyzyASan for crash reporting.
  "src/third_party/crashpad/files":
    "https://chromium.googlesource.com/crashpad/crashpad@35da3b6735",

  # Brings in the open-source Microsoft cvinfo.h file.
  "src/third_party/microsoft-pdb":
    "https://github.com/Microsoft/microsoft-pdb.git@082c529",

  # Capstone is the ultimate disassembler library.
  "src/third_party/capstone/files":
    "https://github.com/aquynh/capstone.git@1b585c1",
}


include_rules = [
  # Everybody can use some things.
  "+base",
  "+build",
]

hooks = [
  {
    # This clobbers when necessary (based on get_landmines.py). It must be
    # called before any other hook that get/generate into the output directory.
    "name": "landmines",
    "pattern": ".",
    "action": [Var("python_path"),
               "src\\syzygy\\build\\landmines_wrapper.py",
               "--landmine-scripts=src\\syzygy\\build\\get_landmines.py",
               "--verbose"],
  },
  {
    "name": "generate_lastchange",
    "pattern": ".",
    "action": [Var("python_path"),
               "src\\syzygy\\build\\lastchange.py",
               "-s", "src\\syzygy",
               "-o", "src\\syzygy\\build\\LASTCHANGE.gen"],
  },
  {
    "name": "generate_base_lastchange",
    "pattern": ".",
    "action": [Var("python_path"),
               "src\\build\\util\\lastchange.py",
               "-s", "src\\base",
               "-o", "src\\build\\util\\LASTCHANGE"],
  },
  {
    "name": "generate_timestamp",
    "pattern": ".",
    "action": [Var("python_path"),
               "src\\syzygy\\build\\timestamp.py",
               "--output", "src\\syzygy\\build\\TIMESTAMP.gen"],
  },
  {
    # Update the Windows toolchain if necessary.
    "name": "win_toolchain",
    "pattern": ".",
    "action": [Var("python_path"), "src/syzygy/build/vs_toolchain_wrapper.py",
               "update"],
  },
  {
    "name": "run_gyp",
    "pattern": ".",
    "action": [Var("python_path"),
               Var("gyp_path"),
               "--include=src/build/common.gypi",
               "--include=src/syzygy/syzygy.gypi",
               "--no-circular-check",
               "src/syzygy/build/all.gyp"],
  },
  {
    "name": "download_clang_format",
    "pattern": ".",
    "action": ["download_from_google_storage",
               "--no_resume",
               "--platform=win32",
               "--no_auth",
               "--bucket", "chromium-clang-format",
               "-s", "src/buildtools/win/clang-format.exe.sha1",
    ],
  },
  # Pull the Syzygy binaries, used for Asan self-testing.
  {
    "name": "syzygy-binaries",
    "pattern": ".",
    "action": [Var("python_path"),
               "src/syzygy/build/get_syzygy_binaries.py",
               "--output-dir=src/syzygy/binaries",
               "--revision=0645c685e783c6787acb8f6e1dade4f916605fc1",
               "--overwrite",
    ],
  },
  {
    # Pull Clang binaries,
    # used for compiling and instrumenting with Clang and Asan.
    "name": "clang",
    "pattern": ".",
    "action": ["python", "src/tools/clang/scripts/update.py", "--if-needed"],
  },
]
