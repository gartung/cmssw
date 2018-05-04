  cms_rootdict(DataFormatsHcalDigi classes.h classes_def.xml)
cms_add_library(DataFormatsHcalDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/HcalDetId
                  DataFormats/Common
                )
