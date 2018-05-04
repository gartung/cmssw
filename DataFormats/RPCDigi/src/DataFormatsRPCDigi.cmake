  cms_rootdict(DataFormatsRPCDigi classes.h classes_def.xml)
cms_add_library(DataFormatsRPCDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  CondFormats/RPCObjects
                  DataFormats/MuonDetId
                  DataFormats/Common
                )
