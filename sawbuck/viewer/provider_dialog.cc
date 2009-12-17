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
// Provider dialog implementation.
#include "sawbuck/viewer/provider_dialog.h"
#include <wmistr.h>
#include <evntrace.h>
#include "base/string_util.h"
#include "sawbuck/viewer/viewer_window.h"

namespace {

struct LogLevelInfo {
  UCHAR level;
  const wchar_t* name;
};

const LogLevelInfo kLogLevels[] = {
  TRACE_LEVEL_NONE, L"None",
  TRACE_LEVEL_FATAL, L"Fatal",
  TRACE_LEVEL_ERROR, L"Error",
  TRACE_LEVEL_WARNING ,L"Warning",
  TRACE_LEVEL_INFORMATION, L"Information",
  TRACE_LEVEL_VERBOSE, L"Verbose",
};

int CALLBACK SortByFirstColumn(LPARAM a, LPARAM b, LPARAM wnd) {
  ProviderSettings* settings_a = reinterpret_cast<ProviderSettings*>(a);
  ProviderSettings* settings_b = reinterpret_cast<ProviderSettings*>(b);

  return ::CompareString(LOCALE_NEUTRAL,
                         NORM_IGNORECASE,
                         settings_a->provider_name.c_str(), -1,
                         settings_b->provider_name.c_str(), -1) - CSTR_EQUAL;
}

}  // namespace

ProviderDialog::ProviderDialog(size_t num_providers,
                               ProviderSettings* settings) :
    num_providers_(num_providers), settings_(settings) {
}

BOOL ProviderDialog::OnInitDialog(CWindow focus, LPARAM init_param) {
  CenterWindow();

  providers_.Attach(GetDlgItem(IDC_PROVIDERS));
  providers_.AddColumn(L"Provider", 0);
  providers_.AddColumn(L"Log Level", 1);

  CRect rect;
  providers_.GetClientRect(&rect);
  providers_.SetColumnWidth(0, rect.Width() / 2);
  providers_.SetColumnWidth(1, rect.Width() / 2);

  for (size_t i = 0; i < num_providers_; ++i) {
    providers_.InsertItem(i, settings_[i].provider_name.c_str());
    providers_.SetItemText(i, 1, kLogLevels[settings_[i].log_level].name);
    providers_.SetItemData(i, reinterpret_cast<DWORD_PTR>(&settings_[i]));
  }

  providers_.SortItems(SortByFirstColumn,
                       reinterpret_cast<LPARAM>(providers_.m_hWnd));

  return TRUE;
}

LRESULT ProviderDialog::OnOkCancel(WORD code,
                                   WORD id,
                                   HWND window,
                                   BOOL& handled) {
  ::EndDialog(m_hWnd, id);
  return 0;
}

LRESULT ProviderDialog::OnProviderClick(NMHDR* pnmh) {
  NMITEMACTIVATE* item = reinterpret_cast<NMITEMACTIVATE*>(pnmh);

  // Hit test to find the item/subitem hit;
  LVHITTESTINFO hit_test = {};
  hit_test.pt = item->ptAction;
  if (providers_.SubItemHitTest(&hit_test) == -1)
    return 0;

  // We hit an item.
  CMenu menu;
  menu.CreatePopupMenu();
  wchar_t curr_text[256];
  providers_.GetItemText(hit_test.iItem, 1, curr_text, arraysize(curr_text));

  // We offset our item IDs from zero by an arbitrary constant to
  // be able to distinguish the no selection case from TrackPopupMenu.
  const UINT_PTR kCommandOffset = 0x100;
  for (size_t i = 0; i < arraysize(kLogLevels); ++i) {
    menu.AppendMenu(MF_STRING,
                    kCommandOffset + kLogLevels[i].level,
                    kLogLevels[i].name);
    if (0 == lstrcmpW(kLogLevels[i].name, curr_text))
      menu.CheckMenuItem(kCommandOffset + i, MF_CHECKED);
  }

  POINT pt = item->ptAction;
  ClientToScreen(&pt);
  int id = menu.TrackPopupMenu(TPM_TOPALIGN | TPM_RETURNCMD,
                               pt.x, pt.y, m_hWnd);

  if (id) {
    id -= kCommandOffset;
    int item = hit_test.iItem;
    providers_.SetItemText(item, 1, kLogLevels[id].name);

    ProviderSettings* settings =
        reinterpret_cast<ProviderSettings*>(providers_.GetItemData(item));

    settings->log_level = id;
  }

  return 0;
}
