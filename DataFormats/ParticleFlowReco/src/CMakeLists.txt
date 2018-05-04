  cms_rootdict(DataFormatsParticleFlowReco classes_1.h classes_def_1.xml)
  cms_rootdict(DataFormatsParticleFlowReco classes_2.h classes_def_2.xml)
cms_add_library(DataFormatsParticleFlowReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  vdt_headers
                  rootmath
                  rootcore
                  boost
                  FWCore/Utilities
                  Geometry/CaloGeometry
                  DataFormats/Candidate
                  DataFormats/VertexReco
                  DataFormats/TrajectorySeed
                  DataFormats/TrackReco
                  DataFormats/MuonReco
                  DataFormats/EgammaReco 
                  DataFormats/EgammaCandidates 
                  DataFormats/Common
                  DataFormats/CaloRecHit
                )
