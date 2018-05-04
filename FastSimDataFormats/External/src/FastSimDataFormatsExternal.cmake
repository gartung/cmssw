  cms_rootdict(FastSimDataFormatsExternal classes.h classes_def.xml)
cms_add_library(FastSimDataFormatsExternal
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/DetId
                  DataFormats/GeometrySurface
                  DataFormats/Common
                )
