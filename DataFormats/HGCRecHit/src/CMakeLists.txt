  cms_rootdict(DataFormatsHGCRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsHGCRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/ForwardDetId
                  DataFormats/Common
                  DataFormats/CaloRecHit
                )
