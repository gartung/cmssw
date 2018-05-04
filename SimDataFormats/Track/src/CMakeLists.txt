  cms_rootdict(SimDataFormatsTrack classes.h classes_def.xml)
cms_add_library(SimDataFormatsTrack
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  SimDataFormats/EncodedEventId
                  DataFormats/Math
                  DataFormats/Common
                )
