  cms_rootdict(DataFormatsForwardDetId classes.h classes_def.xml)
cms_add_library(DataFormatsForwardDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/DetId
                  FWCore/Utilities
                )
