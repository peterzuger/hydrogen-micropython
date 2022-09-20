add_library(usermod_hydrogen INTERFACE)

target_sources(usermod_hydrogen INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/hydrogen.c
  ${MICROPY_DIR}/lib/libhydrogen/hydrogen.c
)

target_include_directories(usermod_hydrogen INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}
)

# hydrogen does not need any workarounds for esp32
if(NOT IDF_TARGET STREQUAL "esp32")
  target_compile_definitions(usermod_hydrogen INTERFACE
    PARTICLE
    PLATFORM_ID=3
  )

  # set compile flags for QSTR generation
  set(MICROPY_CPP_FLAGS_EXTRA "-DPARTICLE" "-DPLATFORM_ID=3")
endif()

target_compile_options(usermod_hydrogen INTERFACE
  -Wno-stringop-overflow
  -Wno-stringop-overread
)

target_link_libraries(usermod INTERFACE usermod_hydrogen)
