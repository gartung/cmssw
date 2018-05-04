  cms_rootdict(DataFormatsPhase2TrackerCluster classes.h classes_def.xml)
cms_add_library(DataFormatsPhase2TrackerCluster
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootrflx
                  DataFormats/Phase2TrackerDigi
                  DataFormats/Common
                )
