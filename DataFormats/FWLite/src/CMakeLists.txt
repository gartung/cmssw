  cms_rootdict(DataFormatsFWLite classes.h classes_def.xml)
cms_add_library(DataFormatsFWLite
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootcore
                  FWCore/Utilities
                  FWCore/ParameterSet
                  FWCore/FWLite
                  FWCore/Common
                  DataFormats/Provenance
                  DataFormats/Common
                )
