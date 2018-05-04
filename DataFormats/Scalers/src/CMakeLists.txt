  cms_rootdict(DataFormatsScalers classes.h classes_def.xml)
cms_add_library(DataFormatsScalers
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/Common
                )
