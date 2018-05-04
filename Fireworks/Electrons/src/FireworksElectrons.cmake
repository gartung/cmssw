cms_add_library(FireworksElectrons
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootcore
                  Fireworks/Core
                  DataFormats/EgammaReco
                  Eve
                  Geom
                )
