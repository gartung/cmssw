  cms_rootdict(DataFormatsL1GlobalCaloTrigger classes.h classes_def.xml)
cms_add_library(DataFormatsL1GlobalCaloTrigger
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/L1CaloTrigger
                  DataFormats/Common
                )
