  cms_rootdict(DataFormatsCandidate classes.h classes_def.xml)
cms_add_library(DataFormatsCandidate
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  FWCore/Utilities
                  DataFormats/Math
                  DataFormats/Common
                )
