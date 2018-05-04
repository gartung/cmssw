  cms_rootdict(CondFormatsRPCObjects classes.h classes_def.xml)
cms_add_library(CondFormatsRPCObjects
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost_serialization
                  CondFormats/Serialization
                  boost
                  FWCore/Utilities
                  FWCore/MessageLogger
                  DataFormats/MuonDetId
                  DataFormats/DetId
                )
