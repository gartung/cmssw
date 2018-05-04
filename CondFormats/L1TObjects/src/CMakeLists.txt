  cms_rootdict(CondFormatsL1TObjects classes.h classes_def.xml)
cms_add_library(CondFormatsL1TObjects
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/StdDictionaries
                  DataFormats/L1GlobalTrigger
                  DataFormats/L1GlobalCaloTrigger
                  DataFormats/L1GlobalMuonTrigger
                  FWCore/Utilities
                  FWCore/ParameterSet
                  DataFormats/MuonDetId
                  boost_serialization
                  CondFormats/Serialization
                  boost
                )
