// Copyright 2012 Google Inc. All Rights Reserved.
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
// Declares a generic command-line application framework.
//
// An application can be declared as follows in a library:
//
//     class MyApp : public common::AppImplBase {
//      public:
//       bool ParseCommandLine(const CommandLine* command_line);
//       int Run();
//      protected:
//       bool InternalFunc();
//     };
//
// The application class can then be unit-tested as appropriate. See the
// declaration of common::AppImplBase for the entire interface expected
// by the application framework. Note that derivation from AppImplBase
// is optional, as the integration with the application framework is
// by template expansion, not virtual function invocation; AppImplBase
// is purely a convenience base class to allow you to elide defining
// parts of the interface you don't need to specialize.
//
// The main() function for the executable can be reduced to:
//
//     int main(int argc, const char* const* argv) {
//       base::AtExitManager at_exit_manager;
//       CommandLine::Init(argc, argv);
//       return common::Application<MyApp>().Run();
//     }
//
// To test how your application implementation interacts with the
// application framework. You can run the application directly from
// a unittest as follows:
//
//     TEST(FixtureName, TestName) {
//       using common::Application;
//
//       base::ScopedFILE in(base::OpenFile("NUL", "r"));
//       base::ScopedFILE out(base::OpenFile("NUL", "w"));
//       base::ScopedFILE err(base::OpenFile("NUL", "w"));
//       ASSERT_TRUE(in.get() != NULL);
//       ASSERT_TRUE(out.get() != NULL);
//       ASSERT_TRUE(err.get() != NULL);
//
//       CommandLine cmd_line(base::FilePath(L"program"));
//       Application<MyTestApp, LOG_INIT_NO> test_app(&cmd_line,
//                                                    in.get(),
//                                                    out.get(),
//                                                    err.get());
//
//       ASSERT_TRUE(test_app.implementation().SomeFunc());
//       ASSERT_EQ(0, test_app.Run());
//     }
//

#ifndef SYZYGY_COMMON_APPLICATION_H_
#define SYZYGY_COMMON_APPLICATION_H_

#include <objbase.h>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "syzygy/common/com_utils.h"

namespace common {

// A convenience base class that describes the interface an application
// implementation is expected to expose. This class provides empty default
// method implementations.
//
// @note Each method is responsible for logging its own errors as it deems
//     appropriate. No log messages are otherwise generated if one of the
//     AppImplBase methods returns an error.
class AppImplBase {
 public:
  // Initializes an application implementation with the standard IO streams.
  // Use the stream IO accessors to customize the IO streams.
  // @param name the name of the application.
  explicit AppImplBase(const base::StringPiece& name);

  // Parse the given command line in preparation for execution.
  bool ParseCommandLine(const CommandLine* command_line);

  // A hook called just before Run().
  bool SetUp();

  // The main logic for the application implementation.
  // @returns the exit status for the application.
  int Run();

  // A hook called just after Run().
  void TearDown();

  // Get the application name.
  const std::string& name() const { return name_; }

  // @name IO Stream Accessors
  // @{
  FILE* in() const { return in_; }
  FILE* out() const { return out_; }
  FILE* err() const { return err_; }

  void set_in(FILE* f) {
    DCHECK(f != NULL);
    in_ = f;
  }

  void set_out(FILE* f) {
    DCHECK(f != NULL);
    out_ = f;
  }

  void set_err(FILE* f) {
    DCHECK(f != NULL);
    err_ = f;
  }
  // @}

  // A helper function to return an absolute path (if possible) for the given
  // path. If the conversion to an absolute path fails, the original path is
  // returned.
  static base::FilePath AbsolutePath(const base::FilePath& path);

  // A helper function which appends the set of absolute file paths matching
  // the @p pattern (for example ..\foo\*.bin) to the end of @p matches.
  // @returns true if at least one matching file was found.
  static bool AppendMatchingPaths(const base::FilePath& pattern,
                                  std::vector<base::FilePath>* matches);

  // A helper function to get a command line parameter that has both a current
  // and a deprecated name.
  template <typename ValueType>
  static bool GetDeprecatedSwitch(
      const CommandLine* cmd_line,
      const std::string& current_switch_name,
      const std::string& deprecated_switch_name,
      ValueType (CommandLine::*getter)(const std::string&) const,
      ValueType* value) {
    DCHECK(cmd_line != NULL);
    DCHECK(getter != NULL);
    DCHECK(value != NULL);
    if (cmd_line->HasSwitch(deprecated_switch_name)) {
      if (cmd_line->HasSwitch(current_switch_name)) {
        LOG(ERROR) << "Cannot specify both --" << current_switch_name
                   << " and --" << deprecated_switch_name << ".";
        return false;
      }
      LOG(WARNING)
          << "Using deprecated switch: --" << deprecated_switch_name << ".";
      *value = (cmd_line->*getter)(deprecated_switch_name);
    } else {
      *value = (cmd_line->*getter)(current_switch_name);
    }
    return true;
  }

 protected:
  // The name of this application.
  std::string name_;

  // @name Standard file streams.
  // @{
  FILE* in_;
  FILE* out_;
  FILE* err_;
  // @}
};

// Flags controlling the initialization of the logging subsystem.
enum AppLoggingFlag { INIT_LOGGING_NO, INIT_LOGGING_YES };

// The Application template class.
//
// @tparam Implementation The class which implements the application logic.
// @tparam kInitLogging Tracks whether or not the application should
//     (re-)initialize the logging subsystem on startup. Under testing,
//     for example, one might want to skip initializing the logging
//     subsystem.
template <typename Impl, AppLoggingFlag kInitLogging = INIT_LOGGING_YES>
class Application {
 public:
  // The application implementation class.
  typedef typename Impl Implementation;

  // Initializes the application with the current processes command line and
  // the standard IO streams.
  //
  // @pre CommandLine::Init() has been called prior to the creation of the
  //     application object.
  Application();

  // Accessor for the underlying implementation.
  Implementation& implementation() { return implementation_; }

  // @name Accessors for the command line.
  // @{
  const CommandLine* command_line() const { return command_line_; }

  void set_command_line(const CommandLine* command_line) {
    DCHECK(command_line != NULL);
    command_line_ = command_line;
  }
  // @}

  // Get the application name.
  const std::string& name() const { return implementation_.name(); }

  // The main skeleton for actually running an application.
  // @returns the exit status for the application.
  int Run();

  // @name IO Stream Accessors
  // @{
  FILE* in() const { return implementation_.in(); }
  FILE* out() const { return implementation_.out(); }
  FILE* err() const { return implementation_.err(); }

  void set_in(FILE* f) { implementation_.set_in(f); }
  void set_out(FILE* f) { implementation_.set_out(f); }
  void set_err(FILE* f) { implementation_.set_err(f); }
  // @}

 protected:
  // Initializes the logging subsystem for this application. This includes
  // checking the command line for the --verbose[=level] flag and handling
  // it appropriately.
  bool InitializeLogging();

  // The command line for this application. The referred instance must outlive
  // the application instance.
  const CommandLine* command_line_;

  // The implementation instance for this application. Execution will be
  // delegated to this object.
  Implementation implementation_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Application);
};

// A helper class for timing an activity within a scope.
class ScopedTimeLogger {
 public:
  explicit ScopedTimeLogger(const char* label)
      : label_(label), start_(base::Time::Now()) {
    DCHECK(label != NULL);
    LOG(INFO) << label_ << ".";
  }

  ~ScopedTimeLogger() {
    base::TimeDelta duration = base::Time::Now() - start_;
    LOG(INFO) << label_ << " took " << duration.InSecondsF() << " seconds.";
  }

 private:
  // A labeling phrase for the activity being timed.
  const char* const label_;

  // The time at which the activity began.
  const base::Time start_;
};

}  // namespace common

#include "syzygy/common/application_impl.h"

#endif  // SYZYGY_COMMON_APPLICATION_H_
