  cms_rootdict(DataFormatsTrajectoryState classes.h classes_def.xml)
cms_add_library(DataFormatsTrajectoryState
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootcore
                  boost_header
                )
