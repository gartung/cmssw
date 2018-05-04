  cms_rootdict(DataFormatsBeamSpot classes.h classes_def.xml)
cms_add_library(DataFormatsBeamSpot
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhep
                  rootsmatrix
                  rootcore
                  DataFormats/CLHEP
                  DataFormats/Common
                )
