  cms_rootdict(PhysicsToolsFWLite classes.h classes_def.xml)
cms_add_library(PhysicsToolsFWLite
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/MuonReco
                  DataFormats/FWLite
                  CommonTools/Utils
                  roothistmatrix
                  rootcore
                  boost
                )
