  cms_rootdict(DataFormatsDTDigi classes.h classes_def.xml)
cms_add_library(DataFormatsDTDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/FEDRawData
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
