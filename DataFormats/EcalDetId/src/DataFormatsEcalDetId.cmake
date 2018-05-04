  cms_rootdict(DataFormatsEcalDetId classes.h classes_def.xml)
cms_add_library(DataFormatsEcalDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  FWCore/Utilities
                  DataFormats/DetId
                  DataFormats/Common
                )
