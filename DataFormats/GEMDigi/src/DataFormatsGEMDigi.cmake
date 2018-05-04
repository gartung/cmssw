  cms_rootdict(DataFormatsGEMDigi classes.h classes_def.xml)
cms_add_library(DataFormatsGEMDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
