  cms_rootdict(DataFormatsMuonDetId classes.h classes_def.xml)
cms_add_library(DataFormatsMuonDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  DataFormats/DetId
                )
