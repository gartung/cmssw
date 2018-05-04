  cms_rootdict(DataFormatsSiPixelDigi classes.h classes_def.xml)
cms_add_library(DataFormatsSiPixelDigi
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/SiPixelDetId
                  DataFormats/Common
                )
