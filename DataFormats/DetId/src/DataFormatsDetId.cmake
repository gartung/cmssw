  cms_rootdict(DataFormatsDetId classes.h classes_def.xml)
cms_add_library(DataFormatsDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Common
                  boost
                )
