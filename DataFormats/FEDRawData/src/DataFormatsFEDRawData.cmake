  cms_rootdict(DataFormatsFEDRawData classes.h classes_def.xml)
cms_add_library(DataFormatsFEDRawData
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  DataFormats/Common
                )
