  cms_rootdict(DataFormatsHcalIsolatedTrack classes.h classes_def.xml)
cms_add_library(DataFormatsHcalIsolatedTrack
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/MessageLogger
                  DataFormats/L1Trigger
                  DataFormats/TrackReco
                  DataFormats/RecoCandidate
                  DataFormats/Math
                  DataFormats/Common
                  DataFormats/Candidate
                )
