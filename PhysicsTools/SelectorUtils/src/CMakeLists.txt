  cms_rootdict(PhysicsToolsSelectorUtils classes.h classes_def.xml)
cms_add_library(PhysicsToolsSelectorUtils
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  openssl
                  root
                  rootcore
                  FWCore/Utilities
                  FWCore/ParameterSet
                  FWCore/FWLite
                  FWCore/Common
                  DataFormats/VertexReco
                  DataFormats/Provenance
                  DataFormats/Common
                  DataFormats/BeamSpot
                  DataFormats/TauReco
                  DataFormats/MuonReco
                  DataFormats/EgammaCandidates
                  DataFormats/PatCandidates
                  DataFormats/Candidate
                  DataFormats/Math
                  CommonTools/Utils
                )
