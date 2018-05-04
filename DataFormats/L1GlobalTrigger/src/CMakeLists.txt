  cms_rootdict(DataFormatsL1GlobalTrigger classes.h classes_def.xml)
cms_add_library(DataFormatsL1GlobalTrigger
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  FWCore/Utilities
                  FWCore/MessageLogger
                  DataFormats/L1GlobalMuonTrigger
                  DataFormats/StdDictionaries
                  DataFormats/Provenance
                  DataFormats/Common
                )
