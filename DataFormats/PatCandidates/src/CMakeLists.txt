  cms_rootdict(DataFormatsPatCandidates classes_objects.h classes_def_objects.xml)
  cms_rootdict(DataFormatsPatCandidates classes_trigger.h classes_def_trigger.xml)
  cms_rootdict(DataFormatsPatCandidates classes_user.h classes_def_user.xml)
  cms_rootdict(DataFormatsPatCandidates classes_other.h classes_def_other.xml)
cms_add_library(DataFormatsPatCandidates
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  SimDataFormats/JetMatching
                  DataFormats/EcalRecHit
                  DataFormats/CaloTowers
                  DataFormats/HLTReco
                  DataFormats/L1Trigger
                  CondFormats/L1TObjects
                  DataFormats/BTauReco
                  DataFormats/HepMCCandidate
                  DataFormats/TrackReco
                  DataFormats/ParticleFlowCandidate
                  DataFormats/EgammaCandidates
                  DataFormats/METReco
                  DataFormats/JetReco
                  DataFormats/TauReco
                  DataFormats/MuonReco
                  DataFormats/Candidate
                  DataFormats/StdDictionaries
                  DataFormats/Common
                  FWCore/Common
                  FWCore/Utilities
                )
