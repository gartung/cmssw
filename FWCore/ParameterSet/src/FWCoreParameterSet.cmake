cms_add_library(FWCoreParameterSet
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost_filesystem
                  boost
                  tbb
                  FWCore/Utilities
                  FWCore/PluginManager
                  FWCore/MessageLogger
                  DataFormats/Provenance
                )
