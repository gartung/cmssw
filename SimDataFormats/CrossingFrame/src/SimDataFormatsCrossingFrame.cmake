  cms_rootdict(SimDataFormatsCrossingFrame classes.h classes_def.xml)
cms_add_library(SimDataFormatsCrossingFrame
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  SimDataFormats/GeneratorProducts
                  SimDataFormats/Vertex
                  SimDataFormats/TrackingHit
                  SimDataFormats/Track
                  SimDataFormats/EncodedEventId
                  SimDataFormats/CaloHit
                  FWCore/Utilities
                  FWCore/MessageLogger
                  DataFormats/Provenance
                  DataFormats/HcalDetId
                  DataFormats/Common
                )
