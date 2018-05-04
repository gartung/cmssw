  cms_rootdict(DataFormatsLuminosity classes.h classes_def.xml)
cms_add_library(DataFormatsLuminosity
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/PatCandidates
                  FWCore/Utilities
                  DataFormats/Common
                )
