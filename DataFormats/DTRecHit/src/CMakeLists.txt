  cms_rootdict(DataFormatsDTRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsDTRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  DataFormats/TrackingRecHit
                  DataFormats/MuonDetId
                  DataFormats/GeometryVector
                  DataFormats/GeometrySurface
                  DataFormats/DTDigi
                  DataFormats/Common
                )
