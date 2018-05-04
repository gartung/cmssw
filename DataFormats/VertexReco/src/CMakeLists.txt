  cms_rootdict(DataFormatsVertexReco classes.h classes_def.xml)
cms_add_library(DataFormatsVertexReco
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  DataFormats/TrackReco
                  DataFormats/Common
                )
