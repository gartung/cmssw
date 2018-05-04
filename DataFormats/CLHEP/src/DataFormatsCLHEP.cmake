  cms_rootdict(DataFormatsCLHEP classes.h classes_def.xml)
cms_add_library(DataFormatsCLHEP
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Math
                  rootmath
                  clhep
                )
