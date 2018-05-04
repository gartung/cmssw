  cms_rootdict(FWCoreFWLite classes.h classes_def.xml)
cms_add_library(FWCoreFWLite
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootcore
                  FWCore/Utilities
                  FWCore/PluginManager
                  DataFormats/Provenance
                  DataFormats/Common
                )
