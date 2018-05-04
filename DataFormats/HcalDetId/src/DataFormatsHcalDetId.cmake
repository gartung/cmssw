  cms_rootdict(DataFormatsHcalDetId classes.h classes_def.xml)
cms_add_library(DataFormatsHcalDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  FWCore/Utilities
                  DataFormats/DetId
                )
