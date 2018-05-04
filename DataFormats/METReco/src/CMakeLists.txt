  cms_rootdict(DataFormatsMETReco classes.h classes_def.xml)
cms_add_library(DataFormatsMETReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  root
                  boost
                  FWCore/Utilities
                  DataFormats/HcalRecHit
                  DataFormats/EcalRecHit
                  DataFormats/JetReco
                  DataFormats/RecoCandidate
                  DataFormats/Common
                )
