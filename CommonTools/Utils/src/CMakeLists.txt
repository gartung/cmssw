cms_add_library(CommonToolsUtils
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  roottmva
                  roothistmatrix
                  boost
                  CondFormats/EgammaObjects
                  CondFormats/DataRecord
                  FWCore/MessageLogger
                  FWCore/Utilities
                )
