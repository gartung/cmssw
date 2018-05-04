  cms_rootdict(DataFormatsL1Trigger classes.h classes_def.xml)
cms_add_library(DataFormatsL1Trigger
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/HcalDetId
                  DataFormats/L1GlobalMuonTrigger
                  DataFormats/L1GlobalCaloTrigger
                  DataFormats/Common
                  DataFormats/Candidate
                )
