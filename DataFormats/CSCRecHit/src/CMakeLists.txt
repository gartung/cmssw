  cms_rootdict(DataFormatsCSCRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsCSCRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/TrackingRecHit
                  DataFormats/GeometryVector
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
