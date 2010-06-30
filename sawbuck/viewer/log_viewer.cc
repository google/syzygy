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
// Log viewer window implementation.
#include "sawbuck/viewer/log_viewer.h"

#include <atlbase.h>
#include <atlframe.h>
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "pcrecpp.h"  // NOLINT
#include "sawbuck/viewer/filtered_log_view.h"
#include "sawbuck/viewer/const_config.h"
#include "sawbuck/viewer/preferences.h"


const char kDefaultIncludeRe[] = ".*";
const char kDefaultExcludeRe[] = "";

LogViewer::LogViewer(CUpdateUIBase* update_ui)
    : log_list_view_(update_ui),
      stack_trace_list_view_(update_ui),
      log_view_(NULL),
      update_ui_(update_ui) {
  Preferences prefs;
  prefs.ReadStringValue(config::kIncludeReValue,
                        &include_re_,
                        kDefaultIncludeRe);
  prefs.ReadStringValue(config::kExcludeReValue,
                        &exclude_re_,
                        kDefaultExcludeRe);
}

LogViewer::~LogViewer() {
}

void LogViewer::SetLogView(ILogView* log_view) {
  DCHECK(log_view_ == NULL);

  log_view_ = log_view;
  ApplyFilterExpressions();
}

int LogViewer::OnCreate(LPCREATESTRUCT create_struct) {
  BOOL bHandled = TRUE;
  Super::OnCreate(WM_CREATE,
                  NULL,
                  reinterpret_cast<LPARAM>(create_struct),
                  bHandled);

  // Create the log list view.
  log_list_view_.Create(m_hWnd);

  // Create the stack trace list view.
  stack_trace_list_view_.Create(m_hWnd);

  log_list_view_.set_stack_trace_view(&stack_trace_list_view_);

  SetDefaultActivePane(SPLIT_PANE_TOP);
  SetSplitterPanes(log_list_view_.m_hWnd, stack_trace_list_view_.m_hWnd);
  SetSplitterExtendedStyle(SPLIT_BOTTOMALIGNED);

  // This is enabled so long as we live.
  update_ui_->UIEnable(ID_LOG_FILTER, true);

  SetMsgHandled(FALSE);
  return 1;
}

LRESULT LogViewer::OnCommand(UINT msg,
                             WPARAM wparam,
                             LPARAM lparam,
                             BOOL& handled) {
  HWND window = GetSplitterPane(GetActivePane());
  return ::SendMessage(window, msg, wparam, lparam);
}

namespace {
class FilterDialog: public CDialogImpl<FilterDialog> {
 public:
  BEGIN_MSG_MAP(FilterDialog)
    MSG_WM_INITDIALOG(OnInitDialog)
    COMMAND_ID_HANDLER_EX(IDOK, OnIdOk)
    COMMAND_ID_HANDLER_EX(IDCANCEL, OnIdCancel)
  END_MSG_MAP()

  static const int IDD = IDD_FILTERDIALOG;

  FilterDialog(const std::string& include, const std::string& exclude)
      : include_re_(include), exclude_re_(exclude) {
  }

  const std::string& include_re() const { return include_re_; }
  const std::string& exclude_re() const { return exclude_re_; }

 private:
  BOOL OnInitDialog(CWindow focus_window, LPARAM init_param);
  void OnIdOk(UINT notify_code, int id, CWindow window);
  void OnIdCancel(UINT notify_code, int id, CWindow window);
  bool CheckAndReportRe(const std::string& str, const char* field);

  std::string include_re_;
  std::string exclude_re_;
};

BOOL FilterDialog::OnInitDialog(CWindow focus_window, LPARAM init_param) {
  CenterWindow();

  BOOL success =
      SetDlgItemText(IDC_INCLUDE_RE, UTF8ToWide(include_re_).c_str()) &&
      SetDlgItemText(IDC_EXCLUDE_RE, UTF8ToWide(exclude_re_).c_str());
  DCHECK(success) << "Broken dialog template for filter dialog";

  return TRUE;
}

bool FilterDialog::CheckAndReportRe(const std::string& str,
                                    const char* field) {
  pcrecpp::RE re(str, PCRE_UTF8);

  if (re.error().empty())
    return true;

  // Uh-oh, the regular expression is broken, bark at the user.
  std::stringstream msg;
  msg << "Error in " << field << " expression: " << re.error();
  ::MessageBox(m_hWnd,
               UTF8ToWide(msg.str()).c_str(),
               L"Invalid Regular Expression",
               MB_OK);

  return false;
}

void FilterDialog::OnIdOk(UINT notify_code, int id, CWindow window) {
  wchar_t text_buf[2048];
  size_t len = GetDlgItemText(IDC_INCLUDE_RE, text_buf, arraysize(text_buf));
  std::string include;
  WideToUTF8(text_buf, len, &include);

  if (!CheckAndReportRe(include, "include"))
    return;

  len = GetDlgItemText(IDC_EXCLUDE_RE, text_buf, arraysize(text_buf));
  std::string exclude;
  WideToUTF8(text_buf, len, &exclude);
  if (!CheckAndReportRe(exclude, "exclude"))
    return;

  // Stash the new values.
  include_re_.swap(include);
  exclude_re_.swap(exclude);

  EndDialog(IDOK);
}

void FilterDialog::OnIdCancel(UINT notify_code, int id, CWindow window) {
  EndDialog(IDCANCEL);
}

}  // namespace

void LogViewer::OnLogFilter(UINT code, int id, CWindow window) {
  FilterDialog dialog(include_re_, exclude_re_);

  if (dialog.DoModal(m_hWnd) == IDOK) {
    include_re_ = dialog.include_re();
    exclude_re_ = dialog.exclude_re();

    Preferences prefs;
    if (!prefs.WriteStringValue(config::kIncludeReValue, include_re_) ||
        !prefs.WriteStringValue(config::kExcludeReValue, exclude_re_)) {
      LOG(ERROR) << "Failed to write regular expression settings.";
    }

    ApplyFilterExpressions();
  }
}

void LogViewer::ApplyFilterExpressions() {
  if (include_re_ == kDefaultIncludeRe && exclude_re_ == kDefaultExcludeRe) {
    log_list_view_.SetLogView(log_view_);
  } else {
    scoped_ptr<FilteredLogView> new_view(new FilteredLogView(log_view_));

    bool ret = new_view->SetInclusionRegexp(include_re_.c_str());
    DCHECK(ret) << "Invalid inclusion regular expression";
    if (!exclude_re_.empty()) {
      ret = new_view->SetExclusionRegexp(exclude_re_.c_str());
      DCHECK(ret) << "Invalid exclusion regular expression";
    }

    log_list_view_.SetLogView(new_view.get());

    filtered_log_view_.reset(new_view.release());
  }
}
