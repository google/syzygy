// Copyright 2014 Google Inc. All Rights Reserved.
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
//
// This file contains utilities for emitting performance metrics that
// eventually find their way onto the Syzygy dashboard. All metrics are emitted
// with Syzygy version, git hash, timestamp and build configuration information
// attached.
//
// Metric names are alpha-numeric strings. They are made hierarchical by
// inserted '.', allowing related metrics to be grouped. For example,
// "Syzygy.Asan.Shadow.ScanRightForBracketingBlockEnd" and
// "Syzygy.Asan.Shadow.MarkAsFreed".

#ifndef SYZYGY_TESTING_METRICS_H_
#define SYZYGY_TESTING_METRICS_H_

#include "base/strings/string_piece.h"

namespace testing {

// Emits a single data point in a named metric. The behaviour of the logging
// is controlled by the SYZYGY_UNITTEST_METRICS environment variable, which is
// a list of options. The options are as follows:
//   --emit-to-log
//     Causes the metric to be logged to the metrics log.
//   --emit-to-waterfall
//     Causes the metric to be logged to the waterfall.
// If neither are present the metric will simply be emitted via logging.
// @param name The name of the metric.
// @param value The value of the metric.
void EmitMetric(const base::StringPiece& name, int64_t value);
void EmitMetric(const base::StringPiece& name, uint64_t value);
void EmitMetric(const base::StringPiece& name, double value);

}  // namespace testing

#endif  // SYZYGY_TESTING_METRICS_H_
