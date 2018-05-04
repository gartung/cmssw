  cms_rootdict(DataFormatsSiPixelCluster classes.h classes_def.xml)
cms_add_library(DataFormatsSiPixelCluster
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Common
                )
