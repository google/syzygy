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
    """Responds with information about clients.

    If no metric_id is specified, a list of available metrics for the client
    is returned. If a metric_id is specified, information about that metric
    is returned.

    Args:
      client_id: The client ID.
      metric_id: The metric ID. Maybe be an empty string.
    """
    self.response.headers['Content-Type'] = 'application/json'

    client = client_db.Client.get_by_key_name(client_id)
    if not client:
      self.error(404)  # Not found.
      return

    if metric_id:
      metric = metric_db.Metric.get_by_key_name(metric_id, client)
      if not metric:
        self.error(404)  # Not found.
        return

      data = {'id': metric.key().id_or_name(),
              'description': metric.description,
              'units': metric.units}
    else:
      metrics = metric_db.Metric.all()
      metrics.ancestor(client)

      data = []
      for metric in metrics:
        data.append({'id': metric.key().id_or_name(),
                     'description': metric.description,
                     'units': metric.units})

    json.dump(data, self.response.out)

  def post(self, client_id, _):
    """Creates a new metric.

    Adds a metric to the data store. The ID, description and units should be
    specified in the body of the request. The response is 'OK' on success or
    an error message on failure.

    Args:
      client_id: The client ID.
    """
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

    # Creates a new metric or updates the parent, description and units for an
    # existing metric.
    metric = metric_db.Metric(key_name=id, parent=client, description=desc,
                              units=units)
    metric.put()
