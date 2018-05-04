  cms_rootdict(SimDataFormatsRandomEngine classes.h classes_def.xml)
cms_add_library(SimDataFormatsRandomEngine
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  FWCore/Utilities
                  DataFormats/Common
                )
