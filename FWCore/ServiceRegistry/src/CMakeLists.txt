cms_add_library(FWCoreServiceRegistry
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  FWCore/PythonParameterSet
                  FWCore/PluginManager
                  FWCore/ParameterSet
                  DataFormats/Provenance
                )
