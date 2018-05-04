  cms_rootdict(DataFormatsProvenance classes.h classes_def.xml)
cms_add_library(DataFormatsProvenance
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/MessageLogger
                  tbb
                  rootcore
                  boost
                  FWCore/Utilities
                )
