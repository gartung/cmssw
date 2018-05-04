  cms_rootdict(DataFormatsHcalRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsHcalRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/HcalDigi
                  DataFormats/HcalDetId
                  DataFormats/Common
                  DataFormats/CaloRecHit
                )
