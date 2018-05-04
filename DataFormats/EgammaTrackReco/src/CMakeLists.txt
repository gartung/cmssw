  cms_rootdict(DataFormatsEgammaTrackReco classes.h classes_def.xml)
cms_add_library(DataFormatsEgammaTrackReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhepheader
                  DataFormats/TrackReco
                  DataFormats/Common
                  TrackingTools/PatternTools
                )
