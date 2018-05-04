  cms_rootdict(FWCoreCommon classes.h classes_def.xml)
cms_add_library(FWCoreCommon
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  FWCore/Utilities
                  FWCore/ParameterSet
                  DataFormats/Provenance
                )
