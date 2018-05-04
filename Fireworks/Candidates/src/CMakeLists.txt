cms_add_library(FireworksCandidates
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  Fireworks/Calo
                  Fireworks/Core
                  boost_system
                  DataFormats/PatCandidates
                  DataFormats/Candidate
                  Eve
                )
