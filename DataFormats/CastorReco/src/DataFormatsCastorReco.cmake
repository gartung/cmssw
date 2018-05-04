  cms_rootdict(DataFormatsCastorReco classes.h classes_def.xml)
cms_add_library(DataFormatsCastorReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/HcalRecHit
                  DataFormats/Candidate
                  DataFormats/Common
                )
