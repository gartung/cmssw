  cms_rootdict(DataFormatsSiPixelDetId classes.h classes_def.xml)
cms_add_library(DataFormatsSiPixelDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/MessageLogger
                  DataFormats/DetId
                )
