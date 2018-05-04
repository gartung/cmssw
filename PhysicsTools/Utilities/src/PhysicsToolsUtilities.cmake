  cms_rootdict(PhysicsToolsUtilities classes.h classes_def.xml)
cms_add_library(PhysicsToolsUtilities
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  root
                  rootcore
                  roofit
                  SimDataFormats/PileupSummaryInfo
                  FWCore/Common
                  FWCore/Utilities
                  DataFormats/Provenance
                  DataFormats/Common
                )
