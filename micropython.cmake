add_library(usermod_hydrogen INTERFACE)

target_sources(usermod_hydrogen INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/hydrogen.c
  ${MICROPY_DIR}/lib/libhydrogen/hydrogen.c
)

target_include_directories(usermod_hydrogen INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}
)

target_compile_definitions(usermod_hydrogen INTERFACE
  PARTICLE
  PLATFORM_ID=3
)

target_compile_options(usermod_hydrogen INTERFACE
  -Wno-stringop-overflow
  -Wno-stringop-overread
)

# set compile flags for QSTR generation
list(APPEND MICROPY_CPP_FLAGS_EXTRA "-DPARTICLE" "-DPLATFORM_ID=3")

target_link_libraries(usermod INTERFACE usermod_hydrogen)
