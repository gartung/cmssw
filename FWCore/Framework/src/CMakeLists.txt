cms_add_library(FWCoreFramework
                SOURCES
                  *.cc *.cxx *.f *.f77 */*.cc */*.cxx */*.f */*.f77
                PUBLIC
                  rootcore
                  boost
                  FWCore/Version
                  FWCore/Utilities
                  FWCore/ServiceRegistry
                  FWCore/PythonParameterSet
                  FWCore/PluginManager
                  FWCore/ParameterSet
                  FWCore/MessageLogger
                  FWCore/Concurrency
                  FWCore/Common
                  DataFormats/Provenance
                  DataFormats/Common
                )
