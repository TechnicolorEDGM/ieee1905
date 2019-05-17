############## COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE ############
## Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          
## All Rights Reserved                                                      
## The source code form of this Open Source Project components              
## is subject to the terms of the BSD-2-Clause-Patent.                      
## You can redistribute it and/or modify it under the terms of              
## the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) 
## See COPYING file/LICENSE file for more details.          
                
#  
# Copyright (c) 2017, Broadband Forum
# Copyright (c) 2017, MaxLinear, Inc. and its affiliates
# 
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following
#    disclaimer in the documentation and/or other materials
#    provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The above license is used as a license under copyright only.
# Please reference the Forum IPR Policy for patent licensing terms
# <https://www.broadband-forum.org/ipr-policy>.
# 
# Any moral rights which are necessary to exercise under the above
# license grant are also deemed granted under this license.

# When calling this Makefile, the following environment variables must be set:
#
#   CC ------------> Path to the compiler
#   CCFLAGS -------> Extra flags to use while compiling
#   LDGLAGS -------> Extra flags to use while linking
#
#   PLATFORM      -> Possible values: "linux"
#   OUTPUT_FOLDER -> Absolute path to the folder where binaries will be built
#
#   COMMON_LIB ----> Absolute path to the "common library" *.a file
#   COMMON_INC ----> Absolute path to the folder containing common (to all
#                    sub-projects) header files
#
#   FACTORY_LIB   -> Absolute path to the "factory library" *.a file 
#   FACTORY_INC   -> Absolute path to the folder containing the "factory
#                    library" header files
#
#   AL_EXE --------> Absolute path to the final AL entity binary
#
#   MKDIR ---------> Tool to create a directory
#

EXE                        := $(AL_EXE)

AL_DIRECTORY               := al
AL_DIRECTORY_LIB               := al_lib

# "Common" library. Includes platform specific code that is used by both the
# AL and HLE entities (example: "PLATFORM_MALLOC()", "PLATFORM_PRINTF()", ...)
#
AL_LIB    := $(OUTPUT_FOLDER)/libal.so
AL    := -lal


SRC_INDEPENDENT            := src_independent/al_extension.c  src_independent/al_extension_register.c src_independent/al_recv.c  src_independent/al_send.c  src_independent/al_utils.c  src_independent/al_wsc.c  src_independent/al_datamodel.c src_independent/al_entity.c
SRC_INDEPENDENT            += $(wildcard src_independent/extensions/*/*.c)
SRC_PLATFORM_LIB               := src_$(PLATFORM)/platform_os.c src_$(PLATFORM)/platform_interfaces.c src_$(PLATFORM)/platform_crypto.c src_$(PLATFORM)/platform_alme_server.c $(wildcard  src_$(PLATFORM)/platform_interfaces_*.c) 
OBJ_INDEPENDENT            := $(patsubst %.c,$(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/%.o,$(SRC_INDEPENDENT))
OBJ_PLATFORM_LIB               := $(patsubst %.c,$(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/%.o,$(SRC_PLATFORM_LIB))
SRC_PLATFORM               := src_$(PLATFORM)/al_entity_main.c 

OBJ_PLATFORM               := $(patsubst %.c,$(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY)/%.o,$(SRC_PLATFORM))

INTERNAL_INC_INDEPENDENT   := src_independent internal_interfaces 
INTERNAL_INC_INDEPENDENT   += $(sort $(dir $(wildcard interfaces/extensions/*/))) $(sort $(dir $(wildcard  src_independent/extensions/*/)))
INTERNAL_INC_PLATFORM      := src_$(PLATFORM) internal_interfaces

EXTERNAL_INC               := $(COMMON_INC) $(FACTORY_INC)

HDR_INDEPENDENT            := $(shell find $(INTERNAL_INC_INDEPENDENT) $(EXTERNAL_INC) -name *.h)
HDR_PLATFORM               := $(shell find $(INTERNAL_INC_PLATFORM)    $(EXTERNAL_INC) -name *.h)

################################################################################
# Targets
################################################################################

.PHONY: all
all: $(EXE)


$(EXE):  $(OBJ_PLATFORM) $(AL_LIB) $(FACTORY_LIB) $(COMMON_LIB) 
	$(CC) $(OBJ_PLATFORM) $(AL) $(FACTORY) $(COMMON) $(LDFLAGS)  -o $@
$(AL_LIB): $(OBJ_INDEPENDENT) $(OBJ_PLATFORM_LIB)
	$(CC) -shared $(LDFLAGS) $(OBJ_INDEPENDENT) $(OBJ_PLATFORM_LIB) -o $(AL_LIB)	
$(OBJ_INDEPENDENT) : $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/%.o : %.c $(HDR_INDEPENDENT)
	$(foreach directory, $(sort $(dir $(wildcard $(SRC_INDEPENDENT)))), $(MKDIR) $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/$(directory);)
	$(CC) -fPIC $(CCFLAGS) -c  $(addprefix -I,$(INTERNAL_INC_INDEPENDENT) $(EXTERNAL_INC)) $< -o $@
$(OBJ_PLATFORM_LIB)    : $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/%.o : %.c $(HDR_PLATFORM)
	$(foreach directory, $(sort $(dir $(wildcard $(SRC_PLATFORM_LIB)))), $(MKDIR) $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY_LIB)/$(directory);)
	$(CC) -fPIC $(CCFLAGS) -c $(addprefix -I,$(INTERNAL_INC_PLATFORM) $(EXTERNAL_INC) $(INTERNAL_INC_INDEPENDENT)) $< -o $@

$(OBJ_PLATFORM)    : $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY)/%.o : %.c $(HDR_PLATFORM)
	$(foreach directory, $(sort $(dir $(wildcard $(SRC_PLATFORM)))), $(MKDIR) $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY)/$(directory);)
	$(CC) $(CCFLAGS) -c $(addprefix -I,$(INTERNAL_INC_PLATFORM) $(EXTERNAL_INC)) $< -o $@


.PHONY: clean
clean:
	rm -rf $(EXE)
	rm -rf $(AL_LIB)
	rm -rf $(OUTPUT_FOLDER)/tmp/$(AL_DIRECTORY)
