cms_add_library(GeometryCaloGeometry
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhep
                  DataFormats/GeometryVector
                  DataFormats/CaloTowers
                  DataFormats/HcalDetId
                  DataFormats/EcalDetId
                )
