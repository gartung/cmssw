  cms_rootdict(SimDataFormatsTrackingAnalysis classes.h classes_def.xml)
cms_add_library(SimDataFormatsTrackingAnalysis
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  clhepheader
                  SimDataFormats/Vertex
                  SimDataFormats/TrackingHit
                  SimDataFormats/Track
                  SimDataFormats/GeneratorProducts
                  SimDataFormats/EncodedEventId
                  DataFormats/HepMCCandidate
                  DataFormats/TrackReco
                  DataFormats/Math
                  DataFormats/Common
                  DataFormats/Candidate
                )
