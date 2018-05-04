  cms_rootdict(SimDataFormatsTrackerDigiSimLink classes.h classes_def.xml)
cms_add_library(SimDataFormatsTrackerDigiSimLink
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  SimDataFormats/EncodedEventId
                  DataFormats/Common
                )
