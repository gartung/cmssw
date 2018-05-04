  cms_rootdict(DataFormatsEcalRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsEcalRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/EcalDetId
                  DataFormats/Common
                  DataFormats/CaloRecHit
                )
