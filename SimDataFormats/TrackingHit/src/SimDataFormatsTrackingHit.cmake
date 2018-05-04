  cms_rootdict(SimDataFormatsTrackingHit classes.h classes_def.xml)
cms_add_library(SimDataFormatsTrackingHit
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  SimDataFormats/EncodedEventId
                  DataFormats/GeometryVector
                  DataFormats/Common
                )
