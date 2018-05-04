cms_add_library(FWCoreUtilities
                SOURCES
                  *.cc *.cxx *.f *.f77
                PUBLIC
                  md5
                  tbb
                  libuuid
                  rootcore
                  boost_regex
                  boost_filesystem
                  boost
                )
