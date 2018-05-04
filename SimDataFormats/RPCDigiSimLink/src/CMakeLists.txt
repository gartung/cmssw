  cms_rootdict(SimDataFormatsRPCDigiSimLink classes.h classes_def.xml)
cms_add_library(SimDataFormatsRPCDigiSimLink
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  SimDataFormats/TrackingHit
                  SimDataFormats/EncodedEventId
                  DataFormats/Common
                )
