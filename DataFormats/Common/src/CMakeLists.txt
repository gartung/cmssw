  cms_rootdict(DataFormatsCommon classes.h classes_def.xml)
cms_add_library(DataFormatsCommon
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/StdDictionaries
                  FWCore/Utilities
                  FWCore/MessageLogger
                  DataFormats/Provenance
                )
