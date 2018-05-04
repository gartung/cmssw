cms_add_library(FireworksParticleFlow
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  Fireworks/Calo
                  Fireworks/Tracks
                  Fireworks/Candidates
                  Fireworks/Core
                  DataFormats/ParticleFlowCandidate
                  Eve
                )
