cms_add_library(FWCorePythonParameterSet
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost_python
                  boost
                  FWCore/Utilities
                  FWCore/ParameterSet
                  DataFormats/Provenance
                )
