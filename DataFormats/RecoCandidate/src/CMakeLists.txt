  cms_rootdict(DataFormatsRecoCandidate classes.h classes_def.xml)
cms_add_library(DataFormatsRecoCandidate
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  SimDataFormats/GeneratorProducts
                  clhep
                  DataFormats/EgammaReco
                  DataFormats/CaloTowers
                  DataFormats/TrackReco
                  DataFormats/Common
                  DataFormats/Candidate
                  DataFormats/CaloRecHit
                )
