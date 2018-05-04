  cms_rootdict(FWCoreMessageLogger classes.h classes_def.xml)
cms_add_library(FWCoreMessageLogger
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  tbb
                  tinyxml
                  boost
                  FWCore/Utilities
                )
