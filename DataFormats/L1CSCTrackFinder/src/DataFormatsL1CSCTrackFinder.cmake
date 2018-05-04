  cms_rootdict(DataFormatsL1CSCTrackFinder classes.h classes_def.xml)
cms_add_library(DataFormatsL1CSCTrackFinder
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/MuonDetId
                  DataFormats/L1GlobalMuonTrigger
                  DataFormats/DetId
                  DataFormats/Common
                  DataFormats/CSCDigi
                )
