HYDROGEN_MOD_DIR := $(USERMOD_DIR)

# Add all C files to SRC_USERMOD
SRC_USERMOD += $(HYDROGEN_MOD_DIR)/hydrogen.c
SRC_C += lib/libhydrogen/hydrogen.c

# workaround for GCC11 array bound warnings
CFLAGS += -Wno-stringop-overflow -Wno-stringop-overread

# If not compiling for unix
ifdef BOARD
CFLAGS += -I$(HYDROGEN_MOD_DIR) -DPARTICLE -DPLATFORM_ID=3
endif
