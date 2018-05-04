  cms_rootdict(DataFormatsHepMCCandidate classes.h classes_def.xml)
cms_add_library(DataFormatsHepMCCandidate
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  root
                  DataFormats/StdDictionaries
                  DataFormats/Common
                  DataFormats/Candidate
                )
