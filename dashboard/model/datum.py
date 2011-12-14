# Copyright 2011 Google Inc.
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

from google.appengine.ext import db

class Datum(db.Model):
  # Parent: The parent of a Datum entity is a Metric.

  # The time at which the datum was measured. This is populated from the JSON
  # 'timestamp' key or set to the current time if not provided.
  timestamp = db.DateTimeProperty(required=True)

  # A non-empty list of values, populated from the JSON 'values' key.
  values = db.ListProperty(float, required=True)
