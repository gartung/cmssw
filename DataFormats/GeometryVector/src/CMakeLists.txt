  cms_rootdict(DataFormatsGeometryVector classes.h classes_def.xml)
cms_add_library(DataFormatsGeometryVector
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Math
                  rootmath
                )
