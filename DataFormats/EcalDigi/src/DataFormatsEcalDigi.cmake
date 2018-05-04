  cms_rootdict(DataFormatsEcalDigi classes.h classes_def.xml)
cms_add_library(DataFormatsEcalDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/EcalDetId
                  DataFormats/Common
                )
