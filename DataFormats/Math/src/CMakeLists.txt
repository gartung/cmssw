  cms_rootdict(DataFormatsMath classes.h classes_def.xml)
cms_add_library(DataFormatsMath
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootmath
                  DataFormats/Common
                )
