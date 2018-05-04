  cms_rootdict(DataFormatsParticleFlowCandidate classes.h classes_def.xml)
cms_add_library(DataFormatsParticleFlowCandidate
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhepheader
                  rootmath
                  rootcore
                  FWCore/Utilities
                  DataFormats/CSCRecHit
                  DataFormats/DTRecHit
                  DataFormats/GsfTrackReco
                  DataFormats/TrackReco
                  DataFormats/Math
                  DataFormats/Common
                  DataFormats/Candidate
                  DataFormats/EgammaCandidates
                  DataFormats/ParticleFlowReco
                )
