cms_add_library(GeometryCommonDetUnit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhep
                  FWCore/Utilities
                  DataFormats/DetId
                  DataFormats/GeometrySurface
                )
