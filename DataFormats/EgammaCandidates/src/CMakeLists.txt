  cms_rootdict(DataFormatsEgammaCandidates classes.h classes_def.xml)
cms_add_library(DataFormatsEgammaCandidates
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/MessageLogger
                  DataFormats/GeometryCommonDetAlgo
                  DataFormats/GsfTrackReco
                  DataFormats/VertexReco
                  DataFormats/TrackingRecHit
                  DataFormats/TrackerRecHit2D
                  DataFormats/TrackReco
                  DataFormats/RecoCandidate
                  DataFormats/Math
                  DataFormats/CaloTowers
                  DataFormats/CaloRecHit
                  DataFormats/EgammaReco
                  DataFormats/Common
                  DataFormats/CLHEP
                  DataFormats/Candidate
                )
