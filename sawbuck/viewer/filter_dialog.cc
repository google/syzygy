// Copyright 2010 Google Inc.
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
// Filter dialog implementation.

#include "sawbuck/viewer/filter_dialog.h"

#include <atldlgs.h>

#include "base/file_util.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/log_list_view.h"
#include "sawbuck/viewer/preferences.h"

// Filter list view constants:
const FilterListView::ColumnInfo FilterListView::kColumns[] = {
  { 80, L"Column" },
  { 80, L"Relation" },
  { 240, L"Value" },
  { 80, L"Action" },
};
const wchar_t* FilterListView::kConfigKeyName =
    config::kSettingsKey;
const wchar_t* FilterListView::kColumnOrderValueName =
    config::kFilterViewColumnOrder;
const wchar_t* FilterListView::kColumnWidthValueName =
    config::kFilterViewColumnWidths;

FilterListView::FilterListView() {
  COMPILE_ASSERT(arraysize(kColumns) == COL_MAX,
                 wrong_number_of_column_info);
}

// Filter dialog control constants:
const wchar_t* FilterDialog::kColumns[] = {
  L"Severity",
  L"Process ID",
  L"Thread ID",
  L"Time",
  L"File",
  L"Line",
  L"Message",
};

const wchar_t* FilterDialog::kRelations[] = {
  L"is",
  L"contains",
};

const wchar_t* FilterDialog::kActions[] = {
  L"include",
  L"exclude",
};

template <size_t N>
void PopulateCombobox(CComboBox* combo_box, const wchar_t* (&strings)[N]) {
  DCHECK(combo_box);
  for (int i = 0; i < N; i++) {
    combo_box->AddString(strings[i]);
  }
  combo_box->SetCurSel(0);
}

BOOL FilterDialog::OnInitDialog(CWindow focus_window, LPARAM init_param) {
  DlgResize_Init();
  CenterWindow();

  HWND hwnd_list = GetDlgItem(IDC_FILTER_LIST);
  filter_list_view_.Attach(hwnd_list);
  filter_list_view_.AddColumns();
  // Set the extended styles we desire.
  const DWORD kStyles =
      LVS_EX_ONECLICKACTIVATE | LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT;
  filter_list_view_.SetExtendedListViewStyle(kStyles, kStyles);

  column_dropdown_.Attach(GetDlgItem(IDC_FILTER_COLUMN));
  PopulateCombobox(&column_dropdown_, kColumns);

  relation_dropdown_.Attach(GetDlgItem(IDC_FILTER_RELATION));
  PopulateCombobox(&relation_dropdown_, kRelations);

  action_dropdown_.Attach(GetDlgItem(IDC_FILTER_ACTION));
  PopulateCombobox(&action_dropdown_, kActions);

  value_dropdown_.Attach(GetDlgItem(IDC_FILTER_TEXT));

  add_filter_button_.Attach(GetDlgItem(IDC_FILTER_ADD));
  DCHECK(add_filter_button_.m_hWnd);
  remove_filter_button_.Attach(GetDlgItem(IDC_FILTER_REMOVE));
  DCHECK(remove_filter_button_.m_hWnd);
  reset_filter_button_.Attach(GetDlgItem(IDC_FILTER_RESET));
  DCHECK(reset_filter_button_.m_hWnd);

  Preferences pref;
  std::string stored;
  if (pref.ReadStringValue(config::kFilterValues, &stored, "")) {
    filters_ = Filter::DeserializeFilters(stored);
  }

  if (filters_.empty()) {
    reset_filter_button_.EnableWindow(FALSE);
  }

  PopulateFilterList();

  return TRUE;
}

void FilterDialog::PopulateFilterList() {
  filter_list_view_.DeleteAllItems();

  std::vector<Filter>::const_iterator iter(filters_.begin());
  int item = 0;
  for (; iter != filters_.end(); ++iter, ++item) {
    filter_list_view_.AddItem(item, 0, FilterDialog::kColumns[iter->column()]);
    filter_list_view_.AddItem(item, 1,
                              FilterDialog::kRelations[iter->relation()]);
    filter_list_view_.AddItem(item, 2, UTF8ToWide(iter->value()).c_str());
    filter_list_view_.AddItem(item, 3, FilterDialog::kActions[iter->action()]);
  }
}


void FilterDialog::OnClose() {
  OnIdCancel(0, 0, 0);
}

void FilterDialog::OnDestroy() {
  filter_list_view_.Detach();
}

void FilterDialog::OnIdOk(UINT notify_code, int id, CWindow window) {
  EndDialog(IDOK);
}

void FilterDialog::OnIdCancel(UINT notify_code, int id, CWindow window) {
  EndDialog(IDCANCEL);
}

void FilterDialog::OnFilterAdd(UINT notify_code, int id, CWindow window) {
  // Get the filter data:
  int column = column_dropdown_.GetCurSel();
  int relation = relation_dropdown_.GetCurSel();
  int action = action_dropdown_.GetCurSel();

  // Get the filter text... me wishes we used CString.
  std::wstring value;
  int length = value_dropdown_.GetWindowTextLength();
  value.resize(length);
  value_dropdown_.GetWindowText(&value[0], length + 1);

  Filter filter(static_cast<Filter::Column>(column),
                static_cast<Filter::Relation>(relation),
                static_cast<Filter::Action>(action),
                value.c_str());
  filters_.push_back(filter);

  PopulateFilterList();

  // Select the last item in the list (should be the just added filter):
  filter_list_view_.SelectItem(filter_list_view_.GetItemCount() - 1);

  // Enable the Reset button, in case it was disabled.
  reset_filter_button_.EnableWindow();
}

void FilterDialog::OnFilterRemove(UINT notify_code, int id, CWindow window) {
  int list_sel = filter_list_view_.GetSelectedIndex();
  if (list_sel >= 0) {
    size_t index = static_cast<size_t>(list_sel);
    DCHECK(index < filters_.size());
    filters_.erase(filters_.begin() + index);

    // Refresh the list.
    PopulateFilterList();

    int new_count = filter_list_view_.GetItemCount();
    if (new_count == 0) {
      reset_filter_button_.EnableWindow(FALSE);
    } else {
      // Reselect the next item in the list:
      if (list_sel >= filter_list_view_.GetItemCount()) {
          list_sel = filter_list_view_.GetItemCount() - 1;
      }
      filter_list_view_.SelectItem(list_sel);
    }
  }
}

void FilterDialog::OnFilterReset(UINT notify_code, int id, CWindow window) {
  DWORD confirm = ::MessageBox(m_hWnd,
                               L"Are you sure you wish to delete all filters?",
                               L"Confirm Filter Deletion",
                               MB_YESNO | MB_ICONQUESTION);
  if (confirm == IDYES) {
    filters_.clear();
    PopulateFilterList();
    reset_filter_button_.EnableWindow(FALSE);
  }
}

_COMDLG_FILTERSPEC kFilterSpec[] = { {L"Sawbuck Filter File", L"*.flt"} };

void FilterDialog::OnFilterSave(UINT notify_code, int id, CWindow window) {
  CShellFileSaveDialog dialog(L"filters",
                              FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
                                  FOS_OVERWRITEPROMPT | FOS_DONTADDTORECENT,
                              L"flt",
                              &kFilterSpec[0],
                              1);
  if (dialog.DoModal() == IDOK) {
    std::wstring file_path;
    file_path.resize(MAX_PATH);
    if (SUCCEEDED(dialog.GetFilePath(&file_path[0], MAX_PATH - 1))) {
      std::string filter_string = Filter::SerializeFilters(filters_);
      if (file_util::WriteFile(base::FilePath(file_path),
                               &filter_string[0],
                               filter_string.size()) == -1) {
        LOG(ERROR) << "Failed to save filter file to:" << file_path;
        ::MessageBox(m_hWnd, L"Failed to save filter file.",
                     L"File save error.", MB_OK | MB_ICONWARNING);
      }
    }
  }
}

void FilterDialog::OnFilterLoad(UINT notify_code, int id, CWindow window) {
  CShellFileOpenDialog dialog(L"filters",
                              FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
                                  FOS_OVERWRITEPROMPT | FOS_DONTADDTORECENT,
                              L"flt",
                              &kFilterSpec[0],
                              1);
  if (dialog.DoModal() == IDOK) {
    std::wstring file_path;
    file_path.resize(MAX_PATH);
    if (SUCCEEDED(dialog.GetFilePath(&file_path[0], MAX_PATH - 1))) {
      std::string file_contents;
      if (file_util::ReadFileToString(base::FilePath(file_path),
                                      &file_contents)) {
        filters_ = Filter::DeserializeFilters(file_contents);
        PopulateFilterList();
      } else {
        LOG(ERROR) << "Failed to read filter file from:" << file_path;
        ::MessageBox(m_hWnd, L"Failed to read filter file.",
                     L"File read error.", MB_OK | MB_ICONWARNING);
      }
    }
  }
}
