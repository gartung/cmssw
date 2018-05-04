  cms_rootdict(DataFormatsFTLRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsFTLRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/ForwardDetId
                  DataFormats/Common
                  DataFormats/CaloRecHit
                )
