// Copyright 2009 Google Inc.
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
// Configuration-related constants.
#ifndef SAWBUCK_VIEWER_CONST_CONFIG_H_
#define SAWBUCK_VIEWER_CONST_CONFIG_H_

namespace config {

const wchar_t kSettingsKey[] = L"Software\\Google\\SawBuck";
const wchar_t kProviderNamesKey[] = L"Software\\Google\\SawBuck\\Providers";
const wchar_t kProviderLevelsKey[] = L"Software\\Google\\SawBuck\\Levels";

const wchar_t kWindowPosValue[] = L"window_pos";
const wchar_t kLogViewColumnOrder[] = L"log_view_column_order";
const wchar_t kLogViewColumnWidths[] = L"log_view_column_widths";

const wchar_t kStackTraceColumnOrder[] = L"stack_trace_column_order";
const wchar_t kStackTraceColumnWidths[] = L"stack_trace_column_widths";

}  // namespace config

#endif  // SAWBUCK_VIEWER_CONST_CONFIG_H_
