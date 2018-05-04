  cms_rootdict(DataFormatsHistograms classes.h classes_def.xml)
cms_add_library(DataFormatsHistograms
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/Common
                  roothistmatrix
                  boost
                )
