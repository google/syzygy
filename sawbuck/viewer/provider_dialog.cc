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

#include <atltheme.h>
#include <wmistr.h>  // NOLINT. wmistr must precede evntrace.h.
#include <evntrace.h>
#include "base/logging.h"
#include "base/strings/stringprintf.h"

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
  const ProviderConfiguration::Settings* settings_a =
      reinterpret_cast<ProviderConfiguration::Settings*>(a);
  const ProviderConfiguration::Settings* settings_b =
      reinterpret_cast<ProviderConfiguration::Settings*>(b);

  return ::CompareString(LOCALE_NEUTRAL,
                         NORM_IGNORECASE,
                         settings_a->provider_name.c_str(), -1,
                         settings_b->provider_name.c_str(), -1) - CSTR_EQUAL;
}

}  // namespace

using base::StringPrintf;

ProviderDialog::ProviderDialog(ProviderConfiguration* settings)
    : pushed_row_(-1), pushed_col_(-1), settings_(settings) {
}

BOOL ProviderDialog::OnInitDialog(CWindow focus, LPARAM init_param) {
  DlgResize_Init();
  CenterWindow();

  providers_.Attach(GetDlgItem(IDC_PROVIDERS));

  const DWORD kStyles =
      LVS_EX_ONECLICKACTIVATE | LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT;
  providers_.SetExtendedListViewStyle(kStyles, kStyles);
  providers_.AddColumn(L"Provider", COL_NAME);
  providers_.AddColumn(L"Log Level", COL_LEVEL);
  providers_.AddColumn(L"Enable Mask", COL_ENABLE_BITS);

  CRect rect;
  providers_.GetClientRect(&rect);
  for (int col = COL_NAME; col < COL_MAX; ++col)
    providers_.SetColumnWidth(col, rect.Width() / COL_MAX);

  for (size_t i = 0; i < settings_->settings().size(); ++i) {
    const ProviderConfiguration::Settings* settings = &settings_->settings()[i];
    providers_.InsertItem(i, settings->provider_name.c_str());
    providers_.SetItemText(i, COL_LEVEL, kLogLevels[settings->log_level].name);
    providers_.SetItemText(i, COL_ENABLE_BITS,
        StringPrintf(L"0x%08X", settings->enable_flags).c_str());
    providers_.SetItemData(i, reinterpret_cast<DWORD_PTR>(settings));
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

void ProviderDialog::OnContextMenu(CWindow wnd, CPoint point) {
  if (wnd != providers_)
    return;

  // Find the focused element.
  int focused = providers_.GetNextItem(-1, LVNI_FOCUSED);
  if (focused == -1)
    return;

  int col = COL_LEVEL;
  if (point.x != -1 && point.y != -1) {
    // We have a valid point, hit test to find the column.
    LVHITTESTINFO hit_test = {};
    hit_test.pt = point;
    providers_.ScreenToClient(&hit_test.pt);
    if (providers_.SubItemHitTest(&hit_test) != -1)
      col = hit_test.iSubItem;
  }

  DoPopupMenu(focused, col);
}

void ProviderDialog::DoPopupMenu(int item, int col) {
  // Redraw the hit row as pushed.
  pushed_row_ = item;
  pushed_col_ = col;
  providers_.RedrawItems(item, item);
  providers_.UpdateWindow();

  switch (col) {
    case COL_NAME:
      // No popup for name column.
      break;

    case COL_LEVEL:
      DoProviderPopupMenu(item);
      break;
    case COL_ENABLE_BITS:
      DoEnableBitsPopupMenu(item);
      break;
    default:
      NOTREACHED() << "Impossible column";
      break;
  }

  // Redraw the hit row as non-pushed.
  pushed_row_ = -1;
  pushed_col_ = -1;
  providers_.RedrawItems(item, item);
  providers_.UpdateWindow();
}

void ProviderDialog::DoProviderPopupMenu(int item) {
  // We hit an item in the provider column, let's do a popup menu.
  CMenu menu;
  menu.CreatePopupMenu();
  wchar_t curr_text[256];
  providers_.GetItemText(item, COL_LEVEL, curr_text, arraysize(curr_text));

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

  // We display the popupmenu flush with the lower-right hand edge
  // of the item, so make something like a combobox.
  RECT rc = {};
  providers_.GetSubItemRect(item,
                            COL_LEVEL,
                            LVIR_BOUNDS,
                            &rc);

  CPoint pt(rc.right, rc.bottom);
  providers_.ClientToScreen(&pt);
  const UINT kFlags = TPM_TOPALIGN | TPM_RIGHTALIGN | TPM_RETURNCMD |
      TPM_NONOTIFY;
  int id = menu.TrackPopupMenu(kFlags, pt.x, pt.y, m_hWnd);

  if (id) {
    id -= kCommandOffset;
    providers_.SetItemText(item, COL_LEVEL, kLogLevels[id].name);

    ProviderConfiguration::Settings* settings =
        reinterpret_cast<ProviderConfiguration::Settings*>(
            providers_.GetItemData(item));

    settings->log_level = id;
  }
}

void ProviderDialog::DoEnableBitsPopupMenu(int item) {
  CMenu menu;
  menu.CreatePopupMenu();

  ProviderConfiguration::Settings* settings =
      reinterpret_cast<ProviderConfiguration::Settings*>(
          providers_.GetItemData(item));

  const UINT_PTR kSelectAll = 0x001;
  const UINT_PTR kSelectNone = 0x002;
  // We offset our item IDs from zero by an arbitrary constant to
  // be able to distinguish the no selection case from TrackPopupMenu.
  const UINT_PTR kMaskOffset = 0x100;

  menu.AppendMenu(MF_STRING, kSelectAll, L"All");
  menu.AppendMenu(MF_STRING, kSelectNone, L"None");

  for (size_t i = 0; i < settings->flag_names.size(); ++i) {
    UINT_PTR command = kMaskOffset + i;
    menu.AppendMenu(MF_STRING, command, settings->flag_names[i].first.c_str());
    base::win::EtwEventFlags flags = settings->flag_names[i].second;
    if (flags == (flags & settings->enable_flags))
      menu.CheckMenuItem(command, MF_CHECKED);
  }

  // We display the popupmenu flush with the lower-right hand edge
  // of the item, so make something like a combobox.
  RECT rc = {};
  providers_.GetSubItemRect(item,
                            COL_ENABLE_BITS,
                            LVIR_BOUNDS,
                            &rc);

  CPoint pt(rc.right, rc.bottom);
  providers_.ClientToScreen(&pt);
  const UINT kFlags = TPM_TOPALIGN | TPM_RIGHTALIGN | TPM_RETURNCMD |
      TPM_NONOTIFY;
  int id = menu.TrackPopupMenu(kFlags, pt.x, pt.y, m_hWnd);

  switch (id) {
    case 0:
      // Nothing was selected.
      break;
    case kSelectAll:
      settings->enable_flags = 0xFFFFFFFF;
      break;
    case kSelectNone:
      settings->enable_flags = 0x00000000;
      break;

    default:
      DCHECK(id >= kMaskOffset);
      id -= kMaskOffset;
      DCHECK(static_cast<size_t>(id) < settings->flag_names.size());
      base::win::EtwEventFlags selected_flags = settings->flag_names[id].second;
      if (selected_flags == (settings->enable_flags & selected_flags)) {
        // All set, toggle them off.
        settings->enable_flags &= ~selected_flags;
      } else {
        // Some off, toggle them on.
        settings->enable_flags |= selected_flags;
      }
      break;
  }

  providers_.SetItemText(item, COL_ENABLE_BITS,
      StringPrintf(L"0x%08X", settings->enable_flags).c_str());
}

LRESULT ProviderDialog::OnProviderClick(NMHDR* pnmh) {
  NMITEMACTIVATE* item = reinterpret_cast<NMITEMACTIVATE*>(pnmh);

  // Hit test to find the item/subitem hit;
  LVHITTESTINFO hit_test = {};
  hit_test.pt = item->ptAction;
  if (providers_.SubItemHitTest(&hit_test) == -1)
    return 0;

  switch (hit_test.iSubItem) {
    case COL_LEVEL:
    case COL_ENABLE_BITS:
      DoPopupMenu(hit_test.iItem, hit_test.iSubItem);
      break;
  }

  return 0;
}

DWORD ProviderDialog::OnPrePaint(int id, NMCUSTOMDRAW* cust) {
  if (id != IDC_PROVIDERS)
    return CDRF_DODEFAULT;

  // We draw the dropdown arrow after other painting is done.
  return CDRF_NOTIFYITEMDRAW;
}

DWORD ProviderDialog::OnItemPrePaint(int id, NMCUSTOMDRAW* cust) {
  if (id != IDC_PROVIDERS)
    return CDRF_DODEFAULT;

  // We draw the dropdown arrow after other painting is done.
  return CDRF_NOTIFYPOSTPAINT;
}

void ProviderDialog::DrawDropDowns(NMLVCUSTOMDRAW* lv_cust) {
  DrawDropDown(lv_cust, COL_LEVEL);
  DrawDropDown(lv_cust, COL_ENABLE_BITS);
}

void ProviderDialog::DrawDropDown(NMLVCUSTOMDRAW* lv_cust, int col) {
  CDCHandle dc = lv_cust->nmcd.hdc;

  // Calculate the dropdown rect size.
  int dropdown_width = ::GetSystemMetrics(SM_CXVSCROLL);
  int item = lv_cust->nmcd.dwItemSpec;
  RECT rc = {};
  providers_.GetSubItemRect(item, col, LVIR_BOUNDS, &rc);
  rc.left = rc.right - dropdown_width;

  CTheme theme;
  theme.OpenThemeData(providers_, VSCLASS_COMBOBOX);

  bool is_pushed = item == pushed_row_ && col == pushed_col_;
  if (theme.IsThemeNull()) {
    dc.DrawFrameControl(&rc,
                        DFC_SCROLL,
                        DFCS_SCROLLDOWN | (is_pushed ? DFCS_PUSHED : 0));
  } else {
    int state = is_pushed ? CBXS_PRESSED : CBXS_NORMAL;
    theme.DrawThemeBackground(dc, CP_DROPDOWNBUTTON, state, &rc);
  }
}

DWORD ProviderDialog::OnItemPostPaint(int id, NMCUSTOMDRAW* cust) {
  DCHECK_EQ(IDC_PROVIDERS, id);
  NMLVCUSTOMDRAW* lv_cust = reinterpret_cast<NMLVCUSTOMDRAW*>(cust);

  DrawDropDowns(lv_cust);

  return CDRF_DODEFAULT;
}
