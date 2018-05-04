  cms_rootdict(DataFormatsRPCRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsRPCRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/TrackingRecHit
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
