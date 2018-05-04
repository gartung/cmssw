  cms_rootdict(SimDataFormatsDigiSimLinks classes.h classes_def.xml)
cms_add_library(SimDataFormatsDigiSimLinks
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/MuonDetId
                  SimDataFormats/EncodedEventId
                  DataFormats/Common
                )
