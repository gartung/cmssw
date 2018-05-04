  cms_rootdict(DataFormatsTrajectorySeed classes.h classes_def.xml)
cms_add_library(DataFormatsTrajectorySeed
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhepheader
                  Geometry/CommonDetUnit
                  FWCore/Utilities
                  DataFormats/TrackingRecHit
                  DataFormats/SiPixelDetId
                  DataFormats/SiStripDetId
                  DataFormats/TrajectoryState
                  DataFormats/CLHEP
                  DataFormats/Common
                )
