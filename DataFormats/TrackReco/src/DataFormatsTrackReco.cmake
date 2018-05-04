  cms_rootdict(DataFormatsTrackReco classes.h classes_def.xml)
cms_add_library(DataFormatsTrackReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  clhepheader
                  FWCore/Utilities
                  DataFormats/TrackerCommon
                  DataFormats/TrackingRecHit
                  DataFormats/SiStripDetId
                  DataFormats/SiPixelDetId
                  DataFormats/BeamSpot
                  DataFormats/MuonDetId
                  DataFormats/TrackCandidate
                  DataFormats/TrajectoryState
                  DataFormats/Common
                )
