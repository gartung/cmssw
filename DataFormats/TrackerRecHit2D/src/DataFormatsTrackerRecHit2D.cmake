  cms_rootdict(DataFormatsTrackerRecHit2D classes.h classes_def.xml)
cms_add_library(DataFormatsTrackerRecHit2D
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  Geometry/CommonDetUnit
                  FWCore/MessageLogger
                  DataFormats/Phase2TrackerCluster
                  DataFormats/TrajectorySeed
                  DataFormats/TrackingRecHit
                  DataFormats/CLHEP
                  DataFormats/Common
                )
