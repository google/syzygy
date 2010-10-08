# Copyright 2009 Google Inc.
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
# Sawbuck builds on Chrome base, uses GYP, GTest, all of which requires
# this build configuration.

vars = {
  "chrome_revision": "61952",
  "chrome_base": "http://src.chromium.org/svn/trunk",
}

deps = {
  "src/base":
    Var("chrome_base") + "/src/base@" + Var("chrome_revision"),

  "src/skia":
    Var("chrome_base") + "/src/skia@" + Var("chrome_revision"),

  "src/third_party/skia":
    "http://skia.googlecode.com/svn/trunk@364",

  "src/third_party/wtl":
    Var("chrome_base") + "/src/third_party/wtl@" +
        Var("chrome_revision"),

  # NSS, for SSLClientSocketNSS.
  "src/third_party/nss":
    Var("chrome_base") + "/deps/third_party/nss@45059",

  "src/third_party/zlib":
    Var("chrome_base") + "/src/third_party/zlib@" +
        Var("chrome_revision"),
  "src/third_party/libevent":
    Var("chrome_base") + "/src/third_party/libevent@" +
        Var("chrome_revision"),
  "src/third_party/libjpeg":
    Var("chrome_base") + "/src/third_party/libjpeg@" +
        Var("chrome_revision"),
  "src/third_party/icu":
    Var("chrome_base") + "/deps/third_party/icu42@" +
        Var("chrome_revision"),
  "src/third_party/sqlite":
    Var("chrome_base") + "/src/third_party/sqlite@" +
        Var("chrome_revision"),
  "src/third_party/modp_b64":
    Var("chrome_base") + "/src/third_party/modp_b64@" +
        Var("chrome_revision"),

  "src/third_party/distorm/files":
    "http://distorm.googlecode.com/svn/trunk@54",

  "src/third_party/python_24":
    Var("chrome_base") + "/deps/third_party/python_24@22967",

  "src/build":
    Var("chrome_base") + "/src/build@" + Var("chrome_revision"),

  "src/testing":
    Var("chrome_base") + "/src/testing@" + Var("chrome_revision"),
  "src/testing/gtest":
    "http://googletest.googlecode.com/svn/trunk@489",

  "src/tools/gyp":
    "http://gyp.googlecode.com/svn/trunk@818",
}


include_rules = [
  # Everybody can use some things.
  "+base",
  "+build",
]

hooks = [
  {
    # A change to a .gyp, .gypi, or to GYP itself should run the generator.
    "pattern": ".",
    "action": ["python",
               "src/build/gyp_chromium",
               "src/sawbuck/sawbuck.gyp"],
  },
]
