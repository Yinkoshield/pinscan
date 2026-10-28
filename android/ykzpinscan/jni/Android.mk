LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := ykzpinscan
LOCAL_SRC_FILES := pinscan.cpp
# -fno-threadsafe-statics drops __cxa_guard_* (libc++abi) so the module links with
# APP_STL := none; safe because its one local static initialises single-threaded at fork.
LOCAL_CPPFLAGS  := -std=c++17 -fno-exceptions -fno-rtti -fno-threadsafe-statics -Wall -Oz
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
