  cms_rootdict(DataFormatsGEMRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsGEMRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootrflx
                  DataFormats/CSCRecHit
                  DataFormats/GeometryVector
                  DataFormats/TrackingRecHit
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
