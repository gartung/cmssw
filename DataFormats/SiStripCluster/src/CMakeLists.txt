  cms_rootdict(DataFormatsSiStripCluster classes.h classes_def.xml)
cms_add_library(DataFormatsSiStripCluster
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  boost
                  DataFormats/TrajectoryState
                  DataFormats/Common
                )
