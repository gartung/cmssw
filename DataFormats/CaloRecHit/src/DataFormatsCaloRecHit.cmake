  cms_rootdict(DataFormatsCaloRecHit classes.h classes_def.xml)
cms_add_library(DataFormatsCaloRecHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  DataFormats/DetId
                  DataFormats/Common
                )
