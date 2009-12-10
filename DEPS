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
  "chrome_revision": "33066",
}

deps = {
  "src/base":
    "svn://svn.chromium.org/chrome/trunk/src/base@" + Var("chrome_revision"),

  # Ugh, there's a dependency from base to this.
  "src/chrome/third_party/wtl":
    "svn://svn.chromium.org/chrome/trunk/src/chrome/third_party/wtl@" +
        Var("chrome_revision"),
  
  "src/skia":
    "svn://svn.chromium.org/chrome/trunk/src/skia@" + Var("chrome_revision"),

  "src/third_party/skia":
    "http://skia.googlecode.com/svn/trunk@364",
    
  "src/third_party/zlib":
    "svn://svn.chromium.org/chrome/trunk/src/third_party/zlib@" + 
        Var("chrome_revision"),
  "src/third_party/libevent":
    "svn://svn.chromium.org/chrome/trunk/src/third_party/libevent@" + 
        Var("chrome_revision"),
  "src/third_party/libjpeg":
    "svn://svn.chromium.org/chrome/trunk/src/third_party/libjpeg@" + 
        Var("chrome_revision"),
  "src/third_party/icu":
    "svn://svn.chromium.org/chrome/trunk/deps/third_party/icu42@" + 
        Var("chrome_revision"),
  "src/third_party/sqlite":
    "svn://svn.chromium.org/chrome/trunk/src/third_party/sqlite@" + 
        Var("chrome_revision"),
  "src/third_party/modp_b64":
    "svn://svn.chromium.org/chrome/trunk/src/third_party/modp_b64@" + 
        Var("chrome_revision"),
    
  "src/third_party/python_24":
    "svn://svn.chromium.org/chrome/trunk/deps/third_party/python_24@22967",

  "src/build":
    "svn://svn.chromium.org/chrome/trunk/src/build@" + Var("chrome_revision"),

  "src/testing":
    "svn://svn.chromium.org/chrome/trunk/src/testing@" + Var("chrome_revision"),
  "src/testing/gtest":
    "http://googletest.googlecode.com/svn/trunk@336",

  "src/tools/gyp":
    "http://gyp.googlecode.com/svn/trunk@762",
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
