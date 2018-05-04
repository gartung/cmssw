  cms_rootdict(DataFormatsEgammaReco classes.h classes_def.xml)
cms_add_library(DataFormatsEgammaReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/TrackReco
                  DataFormats/TrajectorySeed
                  DataFormats/TrackingRecHit
                  DataFormats/CaloRecHit
                  clhepheader
                  DataFormats/Common
                )
