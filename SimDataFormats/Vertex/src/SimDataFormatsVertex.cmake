  cms_rootdict(SimDataFormatsVertex classes.h classes_def.xml)
cms_add_library(SimDataFormatsVertex
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  SimDataFormats/EncodedEventId
                  DataFormats/Math
                  DataFormats/Common
                )
