  cms_rootdict(DataFormatsCaloTowers classes.h classes_def.xml)
cms_add_library(DataFormatsCaloTowers
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/GeometryVector
                  DataFormats/HcalDetId
                  DataFormats/Candidate
                  FWCore/Utilities
                  DataFormats/Math
                  DataFormats/DetId
                  DataFormats/Common
                )
