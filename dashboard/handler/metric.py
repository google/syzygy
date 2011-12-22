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

import json
from google.appengine.ext import webapp
from model import client as client_db
from model import metric as metric_db


class MetricHandler(webapp.RequestHandler):
  """A class to handle creating and querying metrics."""

  def get(self, client_id, metric_id):
    """Responds with information about metrics.

    If the client does not exist, responds with a 404. If a metric_id is not
    specified, responds with a JSON encoded list of available metrics for the
    client. If a metric_id is specified, responds with JSON encoded
    information about the metric or a 404 if the metric doesn't exist.

    Args:
      client_id: The client ID.
      metric_id: The metric ID. Maybe be an empty string.
    """
    client = client_db.Client.get_by_key_name(client_id)
    if not client:
      self.error(404)  # Not found.
      return

    if metric_id:
      metric = metric_db.Metric.get_by_key_name(metric_id, client)
      if not metric:
        self.error(404)  # Not found.
        return

      result = {'id': metric.key().id_or_name(),
                'description': metric.description,
                'units': metric.units}
    else:
      metrics = metric_db.Metric.all()
      metrics.ancestor(client)

      result = []
      for metric in metrics:
        result.append({'id': metric.key().id_or_name(),
                       'description': metric.description,
                       'units': metric.units})

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, client_id, metric_id):
    """Creates a new metric.

    Adds a metric to the data store. The ID, description and units should be
    specified as POST parameters in the request. Responds with a 200 on success
    or a 400 if there are invalid parameters.

    Args:
      client_id: The client ID.
      metric_id: The metric ID. Must be an empty string.
    """
    if metric_id:
      self.error(400)  # Bad request.
      return

    id = self.request.get('id', None)
    desc = self.request.get('description', None)
    units = self.request.get('units', None)
    if not id or not desc or not units:
      self.error(400)  # Bad request.
      return

    client = client_db.Client.get_by_key_name(client_id)
    if not client:
      self.error(404)  # Not found.
      return

    # Creates a new metric or updates the description and units for an existing
    # metric.
    metric = metric_db.Metric(key_name=id, parent=client, description=desc,
                              units=units)
    metric.put()
