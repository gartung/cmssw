  cms_rootdict(DataFormatsTrackingRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsTrackingRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhep
                  FWCore/Utilities
                  Geometry/CommonDetUnit
                  DataFormats/GeometrySurface
                  DataFormats/CLHEP
                  DataFormats/Common
                )
