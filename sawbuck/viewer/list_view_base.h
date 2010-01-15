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
// List view utility base class.
#ifndef SAWBUCK_VIEWER_LIST_VIEW_BASE_H_
#define SAWBUCK_VIEWER_LIST_VIEW_BASE_H_

#include <atlbase.h>
#include <atlwin.h>
#include <atlctrls.h>

#include "base/logging.h"

// The list view base class knows how to save and restore column order
// and widths.
// @param ImplClass a derivative of this class.
// @note ImplClass must declare the following:
//    # kColumns, an array of ColumnInfo
//    # kConfigKeyName a string that's the configuration key for this window,
//        e.g. L"Software\\MyProg".
//    # kColumnOrderValueName the name of the registry value that persists
//        the column order.
//    # kColumnWidthValueName the name of the registry value that persists
//        the column widths.
template <class ImplClass, class WinTraits>
class ListViewBase
    : public CWindowImpl<ImplClass, CListViewCtrl, WinTraits> {
 public:
  // Describes a column in the list view.
  struct ColumnInfo {
    int width;  // Default width for this column.
    const wchar_t* title;  // Title for this column.
  };

  // Create the columns and restore the order and widths from registry.
  void AddColumns() {
    AddColumns(ImplClass::kColumns,
               ImplClass::kConfigKeyName,
               ImplClass::kColumnOrderValueName,
               ImplClass::kColumnWidthValueName);
  }

  // Save the column order and colum widths for this list view to registry.
  void SaveColumns() {
    SaveColumns(ImplClass::kColumns,
                ImplClass::kConfigKeyName,
                ImplClass::kColumnOrderValueName,
                ImplClass::kColumnWidthValueName);
  }

 private:
  template <int N> void AddColumns(const ColumnInfo (&cols)[N],
                                   const wchar_t* key_name,
                                   const wchar_t* order_value_name,
                                   const wchar_t* width_value_name);
  template <int N> void SaveColumns(const ColumnInfo (&cols)[N],
                                    const wchar_t* key_name,
                                    const wchar_t* order_value_name,
                                    const wchar_t* width_value_name);
};

template <class ImplClass, class WinTraits>
template <int N>
void ListViewBase<ImplClass, WinTraits>::AddColumns(
    const ColumnInfo (&cols)[N], const wchar_t* key_name,
    const wchar_t* order_value_name, const wchar_t* width_value_name) {
  for (int col = 0; col < N; ++col) {
    AddColumn(cols[col].title, col);
    SetColumnWidth(col, cols[col].width);
  }

  // Restore column order and column widths.
  CRegKey settings;
  if (ERROR_SUCCESS == settings.Open(HKEY_CURRENT_USER,
                                     key_name,
                                     KEY_READ)) {
    std::vector<int> cols;
    cols.resize(N);

    ULONG len = cols.size() * sizeof(cols[0]);
    if (ERROR_SUCCESS == settings.QueryBinaryValue(order_value_name,
                                                   &cols[0],
                                                   &len) &&
        len == cols.size() * sizeof(cols[0])) {
      SetColumnOrderArray(cols.size(), &cols[0]);
    }

    len = cols.size() * sizeof(cols[0]);
    if (ERROR_SUCCESS == settings.QueryBinaryValue(width_value_name,
                                                   &cols[0],
                                                   &len) &&
        len == cols.size() * sizeof(cols[0])) {
      for (int col = 0; col < N; ++col) {
        SetColumnWidth(col, cols[col]);
      }
    }
  }
}

template <class ImplClass, class WinTraits>
template <int N>
void ListViewBase<ImplClass, WinTraits>::SaveColumns(
    const ColumnInfo (&cols)[N], const wchar_t* key_name,
    const wchar_t* order_value_name, const wchar_t* width_value_name) {
  // Save column order and widths.
  CRegKey settings;
  if (ERROR_SUCCESS == settings.Create(HKEY_CURRENT_USER,
                                       key_name)) {
    std::vector<int> cols;
    cols.resize(N);

    if (GetColumnOrderArray(cols.size(), &cols[0])) {
      settings.SetBinaryValue(order_value_name,
                              &cols[0],
                              cols.size() * sizeof(cols[0]));
    }

    for (int col = 0; col < N; ++col)
      cols[col] = GetColumnWidth(col);

    settings.SetBinaryValue(width_value_name,
                            &cols[0],
                            cols.size() * sizeof(cols[0]));
  } else {
    LOG(ERROR) << "Unable to open key " << key_name;
  }
}

#endif  // SAWBUCK_VIEWER_LIST_VIEW_BASE_H_
