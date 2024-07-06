#
# Copyright (c) 2016-2023 Moddable Tech, Inc.
#
#   This file is part of the Moddable SDK Tools.
# 
#   The Moddable SDK Tools is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
# 
#   The Moddable SDK Tools is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with the Moddable SDK Tools.  If not, see <http://www.gnu.org/licenses/>.
#

!IF "$(VERBOSE)"=="1"
!CMDSWITCHES -S
!ELSE
!CMDSWITCHES +S
!ENDIF

!IF "$(DEBUG)"=="1"
!IF "$(XSBUG_LOG)"=="1"
START_XSBUG =
!ELSE
START_XSBUG = tasklist /nh /fi "imagename eq xsbug.exe" | find /i "xsbug.exe" > nul || (start $(BUILD_DIR)\bin\win\release\xsbug.exe)
!ENDIF
!ELSE
START_XSBUG =
!ENDIF

!IFNDEF XSBUG_PORT
XSBUG_PORT = 5002
!ENDIF
!IFNDEF XSBUG_HOST
XSBUG_HOST = localhost
!ENDIF

!IF "$(XSBUG_LOG)"=="1"
START_COMMAND = cmd /c "set "XSBUG_PORT=$(XSBUG_PORT)" && set "XSBUG_HOST=$(XSBUG_HOST)" && cd $(MODDABLE)\tools\xsbug-log && node xsbug-log start /B $(SIMULATOR) $(SIMULATORS) $(BIN_DIR)\mc.dll"
!ELSE
START_COMMAND = start $(SIMULATOR) $(SIMULATORS) $(BIN_DIR)\mc.dll
!ENDIF
KILL_COMMAND = taskkill /im mcsim.exe /F 2> nul || (call )

XS_DIRECTORIES = \
	/I$(XS_DIR)\includes \
	/I$(XS_DIR)\platforms \
	/I$(XS_DIR)\sources

XS_HEADERS = \
	$(XS_DIR)\platforms\win_xs.h \
	$(XS_DIR)\platforms\xsPlatform.h \
	$(XS_DIR)\includes\xs.h \
	$(XS_DIR)\includes\xsmc.h \
	$(XS_DIR)\sources\xsCommon.h \
	$(XS_DIR)\sources\xsAll.h \
	$(XS_DIR)\sources\xsScript.h

XS_OBJECTS = \
	$(LIB_DIR)\win_xs.obj \
	$(LIB_DIR)\xsAll.obj \
	$(LIB_DIR)\xsAPI.obj \
	$(LIB_DIR)\xsArguments.obj \
	$(LIB_DIR)\xsArray.obj \
	$(LIB_DIR)\xsAtomics.obj \
	$(LIB_DIR)\xsBigInt.obj \
	$(LIB_DIR)\xsBoolean.obj \
	$(LIB_DIR)\xsCode.obj \
	$(LIB_DIR)\xsCommon.obj \
	$(LIB_DIR)\xsDataView.obj \
	$(LIB_DIR)\xsDate.obj \
	$(LIB_DIR)\xsDebug.obj \
	$(LIB_DIR)\xsError.obj \
	$(LIB_DIR)\xsFunction.obj \
	$(LIB_DIR)\xsGenerator.obj \
	$(LIB_DIR)\xsGlobal.obj \
	$(LIB_DIR)\xsJSON.obj \
	$(LIB_DIR)\xsLexical.obj \
	$(LIB_DIR)\xsMapSet.obj \
	$(LIB_DIR)\xsMarshall.obj \
	$(LIB_DIR)\xsMath.obj \
	$(LIB_DIR)\xsMemory.obj \
	$(LIB_DIR)\xsModule.obj \
	$(LIB_DIR)\xsNumber.obj \
	$(LIB_DIR)\xsObject.obj \
	$(LIB_DIR)\xsPlatforms.obj \
	$(LIB_DIR)\xsPromise.obj \
	$(LIB_DIR)\xsProperty.obj \
	$(LIB_DIR)\xsProxy.obj \
	$(LIB_DIR)\xsRegExp.obj \
	$(LIB_DIR)\xsRun.obj \
	$(LIB_DIR)\xsScope.obj \
	$(LIB_DIR)\xsScript.obj \
	$(LIB_DIR)\xsSourceMap.obj \
	$(LIB_DIR)\xsString.obj \
	$(LIB_DIR)\xsSymbol.obj \
	$(LIB_DIR)\xsSyntaxical.obj \
	$(LIB_DIR)\xsTree.obj \
	$(LIB_DIR)\xsType.obj \
	$(LIB_DIR)\xsdtoa.obj \
	$(LIB_DIR)\xsmc.obj \
	$(LIB_DIR)\xsre.obj

DIRECTORIES = $(DIRECTORIES) $(XS_DIRECTORIES)
	
HEADERS = $(HEADERS) $(XS_HEADERS)

C_DEFINES = \
	/D XS_ARCHIVE=1 \
	/D INCLUDE_XSPLATFORM=1 \
	/D XSPLATFORM=\"win_xs.h\" \
	/D mxRun=1 \
	/D mxNoFunctionLength=1 \
	/D mxNoFunctionName=1 \
	/D mxHostFunctionPrimitive=1 \
	/D mxFewGlobalsTable=1 \
	/D kCommodettoBitmapFormat=$(COMMODETTOBITMAPFORMAT) \
	/D kPocoRotation=$(POCOROTATION)
!IF "$(INSTRUMENT)"=="1"
C_DEFINES = $(C_DEFINES) \
	/D MODINSTRUMENTATION=1 \
	/D mxInstrument=1
!ENDIF

C_INCLUDES = $(DIRECTORIES) /I$(TMP_DIR)

C_FLAGS = \
	/c \
	/D _CONSOLE \
	/D WIN32 \
	/D _CRT_SECURE_NO_DEPRECATE \
	/D HAVE_MEMMOVE=1 \
	/nologo \
	/MP
!IF "$(DEBUG)"=="1"
C_FLAGS = $(C_FLAGS) \
	/D _DEBUG \
	/D mxDebug=1 \
	/Fp$(TMP_DIR)\ \
	/Od \
	/W3 \
	/Z7
!ELSE
C_FLAGS = $(C_FLAGS) \
	/D NDEBUG \
	/Fp$(TMP_DIR)\ \
	/O2 \
	/W0
!ENDIF

LINK_LIBRARIES = ws2_32.lib advapi32.lib comctl32.lib comdlg32.lib gdi32.lib kernel32.lib user32.lib dsound.lib wlanapi.lib Iphlpapi.lib winmm.lib

LINK_OPTIONS = /incremental:no /nologo /dll
!IF "$(DEBUG)"=="1"
LINK_OPTIONS = $(LINK_OPTIONS) /debug
!ENDIF

all: build
	$(KILL_COMMAND)
	$(START_XSBUG)
	$(START_COMMAND)

build: $(LIB_DIR) $(BIN_DIR)\mc.dll

clean:
	echo # Clean project lib, bin and tmp
	echo $(BIN_DIR)
	del /s/q/f $(BIN_DIR)\*.* > NUL
	rmdir /s/q $(BIN_DIR)
	echo $(TMP_DIR)
	del /s/q/f $(TMP_DIR)\*.* > NUL
	rmdir /s/q $(TMP_DIR)
	echo $(LIB_DIR)
	if exist $(LIB_DIR) del /s/q/f $(LIB_DIR)\*.* > NUL
	if exist $(LIB_DIR) rmdir /s/q $(LIB_DIR)

xsbug:
	$(KILL_COMMAND)
	$(START_XSBUG)
	$(START_COMMAND)

$(LIB_DIR) :
	if not exist $(LIB_DIR)\$(NULL) mkdir $(LIB_DIR)

$(BIN_DIR)\mc.dll: $(XS_OBJECTS) $(TMP_DIR)\mc.xs.obj $(TMP_DIR)\mc.resources.obj $(OBJECTS) 
	@echo # link mc.dll
	link $(LINK_OPTIONS) $(LINK_LIBRARIES) $(XS_OBJECTS) $(TMP_DIR)\mc.xs.obj $(TMP_DIR)\mc.resources.obj $(OBJECTS) /implib:$(TMP_DIR)\mc.lib /out:$@
	
$(XS_OBJECTS) : $(XS_HEADERS)
{$(XS_DIR)\sources\}.c{$(LIB_DIR)\}.obj::
	cd $(LIB_DIR)
	cl $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) $<
{$(XS_DIR)\platforms\}.c{$(LIB_DIR)\}.obj::
	cd $(LIB_DIR)
	cl $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) $<

$(TMP_DIR)\mc.xs.obj: $(TMP_DIR)\mc.xs.c $(HEADERS)
	cl $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) $(TMP_DIR)\mc.xs.c /Fo$@
	
$(TMP_DIR)\mc.xs.c: $(MODULES) $(MANIFEST)
	@echo # xsl modules
	xsl <<args.txt 
-b $(MODULES_DIR) -o $(TMP_DIR) $(PRELOADS) $(STRIPS) $(CREATION) $(MODULES)
<<

$(TMP_DIR)\mc.resources.obj: $(TMP_DIR)\mc.resources.c $(HEADERS)
	cl $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) $(TMP_DIR)\mc.resources.c /Fo$@

$(TMP_DIR)\mc.resources.c: $(DATA) $(RESOURCES) $(MANIFEST)
	@echo # mcrez resources
	mcrez <<args.txt
$(DATA) $(RESOURCES) -o $(TMP_DIR) -r mc.resources.c
<<
