  cms_rootdict(DataFormatsGeometryCommonDetAlgo classes.h classes_def.xml)
cms_add_library(DataFormatsGeometryCommonDetAlgo
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  DataFormats/Common
                  DataFormats/GeometryVector
                  DataFormats/GeometrySurface
                  DataFormats/CLHEP
                  DataFormats/Math
                )
