  cms_rootdict(FireworksVertices classes.h classes_def.xml)
cms_add_library(FireworksVertices
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  opengl
                  rootcore
                  Fireworks/Core
                  DataFormats/VertexReco
                  Eve
                  Geom
                  Physics
                  RGL
                  Core
                )
