  cms_rootdict(SimDataFormatsPileupSummaryInfo classes.h classes_def.xml)
cms_add_library(SimDataFormatsPileupSummaryInfo
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  hepmc
                  SimDataFormats/GeneratorProducts
                  DataFormats/Provenance
                  DataFormats/Common
                  DataFormats/Math
                )
