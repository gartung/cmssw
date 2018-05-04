  cms_rootdict(DataFormatsTrackerCommon classes.h classes_def.xml)
cms_add_library(DataFormatsTrackerCommon
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  FWCore/MessageLogger
                  DataFormats/SiPixelDetId
                  DataFormats/SiStripCluster
                  DataFormats/Common
                )
