  cms_rootdict(SimDataFormatsGeneratorProducts classes.h classes_def.xml)
cms_add_library(SimDataFormatsGeneratorProducts
                SOURCES
                  *.cc *.cxx *.f *.f77 *.F
                PUBLIC
                  roothistmatrix
                  xz
                  hepmc
                  DataFormats/Common
                  FWCore/MessageLogger
                  FWCore/Utilities
                )
