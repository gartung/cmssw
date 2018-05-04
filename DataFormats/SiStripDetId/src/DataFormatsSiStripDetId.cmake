  cms_rootdict(DataFormatsSiStripDetId classes.h classes_def.xml)
cms_add_library(DataFormatsSiStripDetId
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/TrackerCommon
                  DataFormats/DetId
                )
