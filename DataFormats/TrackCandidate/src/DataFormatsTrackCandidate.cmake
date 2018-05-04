  cms_rootdict(DataFormatsTrackCandidate classes.h classes_def.xml)
cms_add_library(DataFormatsTrackCandidate
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhepheader
                  DataFormats/TrajectorySeed
                  DataFormats/TrackingRecHit
                  DataFormats/CLHEP
                  DataFormats/Common
                )
