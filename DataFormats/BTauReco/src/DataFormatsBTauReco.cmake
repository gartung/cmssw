  cms_rootdict(DataFormatsBTauReco classes.h classes_def.xml)
cms_add_library(DataFormatsBTauReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  clhep
                  boost
                  FWCore/Utilities
                  DataFormats/VertexReco
                  DataFormats/TrackReco
                  DataFormats/ParticleFlowCandidate
                  DataFormats/Math
                  DataFormats/JetReco
                  DataFormats/Common
                )
