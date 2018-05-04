  cms_rootdict(DataFormatsCSCDigi classes.h classes_def.xml)
cms_add_library(DataFormatsCSCDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/GEMDigi
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
