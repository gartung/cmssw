cms_add_library(FWCorePluginManager
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  boost_filesystem
                  tbb
                  boost
                )
