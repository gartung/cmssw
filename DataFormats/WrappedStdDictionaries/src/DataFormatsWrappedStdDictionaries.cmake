  cms_rootdict(DataFormatsWrappedStdDictionaries classes.h classes_def.xml)
cms_add_library(DataFormatsWrappedStdDictionaries
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Common
                )
