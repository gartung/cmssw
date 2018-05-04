cms_add_library(FireworksMuons
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  Fireworks/Tracks
                  Fireworks/Core
                  Fireworks/Candidates
                  DataFormats/TrackReco
                  DataFormats/MuonReco
                  DataFormats/MuonDetId
                  Eve
                  Geom
                  GeomPainter
                )
