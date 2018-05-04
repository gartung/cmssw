cms_add_library(CommonToolsStatistics
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/MessageLogger
                  DataFormats/CLHEP
                  boost
                  clhep
                )
