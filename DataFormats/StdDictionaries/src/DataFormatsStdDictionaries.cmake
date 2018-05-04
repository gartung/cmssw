  cms_rootdict(DataFormatsStdDictionaries classes_map.h classes_def_map.xml)
  cms_rootdict(DataFormatsStdDictionaries classes_others.h classes_def_others.xml)
  cms_rootdict(DataFormatsStdDictionaries classes_pair.h classes_def_pair.xml)
  cms_rootdict(DataFormatsStdDictionaries classes_vector.h classes_def_vector.xml)
cms_add_library(DataFormatsStdDictionaries
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  rootcore
                )
