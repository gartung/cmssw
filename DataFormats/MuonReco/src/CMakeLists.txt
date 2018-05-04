  cms_rootdict(DataFormatsMuonReco classes.h classes_def.xml)
cms_add_library(DataFormatsMuonReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  DataFormats/VertexReco
                  DataFormats/GEMRecHit
                  DataFormats/CSCRecHit
                  DataFormats/DTRecHit
                  DataFormats/TrackReco
                  DataFormats/RecoCandidate
                  DataFormats/Common
                )
