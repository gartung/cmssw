  cms_rootdict(DataFormatsHLTReco classes.h classes_def.xml)
cms_add_library(DataFormatsHLTReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/Candidate
                  DataFormats/CLHEP
                  DataFormats/Common
                  FWCore/Utilities
                )
