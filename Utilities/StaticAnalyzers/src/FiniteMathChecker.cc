#include "FiniteMathChecker.h"
#include <clang/AST/AST.h>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/DeclGroup.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Expr.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>

#include "CmsSupport.h"
#include <iostream>
#include <memory>

#include <utility>

#include "CmsException.h"

using namespace clang;
using namespace clang::ento;
using namespace llvm;

namespace clangcms {

  class FMWalkAST : public clang::StmtVisitor<FMWalkAST> {
    const CheckerBase *Checker;
    clang::ento::BugReporter &BR;
    clang::AnalysisDeclContext *AC;

  public:
    FMWalkAST(const CheckerBase *checker,
              clang::ento::BugReporter &br,
              clang::AnalysisDeclContext *ac)
        : Checker(checker), BR(br), AC(ac) {}

    // Stmt visitor methods.
    void VisitChildren(clang::Stmt *S);
    void VisitStmt(clang::Stmt *S) { VisitChildren(S); }
    void VisitCallExpr(clang::CallExpr *CE);
  };

  void FMWalkAST::VisitChildren(clang::Stmt *S) {
    for (clang::Stmt *Child: S->children())
      if (Child) {
        Visit(Child);
      }
  }

  void FMWalkAST::VisitCallExpr(clang::CallExpr *CE) {
    const clang::Expr *Callee = CE->getCallee();
    const auto *FD = CE->getReferencedDeclOfCallee()->getAsFunction();
    if (!FD)
      return;

    const char *sfile = BR.getSourceManager().getPresumedLoc(CE->getExprLoc()).getFilename();
    std::string sname(sfile);
    if (!support::isInterestingLocation(sname))
      return;

    // Get the name of the callee.
    auto dname = FD->getName();
    if (!(dname=="isnan") && !(dname=="isinf"))
      return;

    clang::ento::PathDiagnosticLocation CELoc =
        clang::ento::PathDiagnosticLocation::createBegin(CE, BR.getSourceManager(), AC);
    BR.EmitBasicReport(AC->getDecl(), Checker,
                       "Potential use of std::isnan / std::isinf with -ffast-math",
                       "CMS code rules",
                       "std::isnan / std::isinf does not work when fast-math is used." 
                       "Please use "
                       "edm::isNotFinite from 'FWCore/Utilities/interface/isFinite.h'",
                       CELoc, CE->getSourceRange()
                        );
  }

  void FiniteMathChecker::checkASTCodeBody(const clang::Decl *D,
                                       clang::ento::AnalysisManager &mgr,
                                       clang::ento::BugReporter &BR) const {
    const clang::SourceManager &SM = BR.getSourceManager();
    const char *sfile = SM.getPresumedLoc(D->getLocation()).getFilename();
    if (!support::isCmsLocalFile(sfile))
      return;

    FMWalkAST walker(this, BR, mgr.getAnalysisDeclContext(D));
    walker.Visit(D->getBody());
  }
}  // namespace clangcms
