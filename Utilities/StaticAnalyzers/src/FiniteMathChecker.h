#ifndef Utilities_StaticAnalyzers_FastMathChecker_h
#define Utilities_StaticAnalyzers_FastMathChecker_h

#include <clang/StaticAnalyzer/Core/Checker.h>

namespace clangcms {
  class FiniteMathChecker : public clang::ento::Checker<clang::ento::check::ASTCodeBody> {
  public:
    void checkASTCodeBody(const clang::Decl *D,
                      clang::ento::AnalysisManager &mgr,
                      clang::ento::BugReporter &BR) const;
  };
}  // namespace clangcms

#endif
