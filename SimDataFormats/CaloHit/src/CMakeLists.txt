  cms_rootdict(SimDataFormatsCaloHit classes.h classes_def.xml)
cms_add_library(SimDataFormatsCaloHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  SimDataFormats/EncodedEventId
                  DataFormats/Math
                  DataFormats/Common
                )
