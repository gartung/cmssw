  cms_rootdict(DataFormatsGsfTrackReco classes.h classes_def.xml)
cms_add_library(DataFormatsGsfTrackReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  DataFormats/TrackReco
                  DataFormats/Common
                )
