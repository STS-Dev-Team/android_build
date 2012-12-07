###########################################################
## Standard rules for building an executable file.
##
## Additional inputs from base_rules.make:
## None.
###########################################################

# BEGIN MOT GB UPMERGE, a18772, 12/24/2010
# Motorola, a19677, 11/18/09, addon support for Android.mk when building
# java libraries.
ifeq ($(shell stat motorola/$(LOCAL_PATH)/AndroidAppend.mk 2>&1 >/dev/null),)
$(warning including motorola/$(LOCAL_PATH)/AndroidAppend.mk)
include motorola/$(LOCAL_PATH)/AndroidAppend.mk
endif
# End Motorola
# END MOT GB UPMERGE, a18772, 12/24/2010

ifeq ($(strip $(LOCAL_MODULE_CLASS)),)
LOCAL_MODULE_CLASS := EXECUTABLES
endif
ifeq ($(strip $(LOCAL_MODULE_SUFFIX)),)
LOCAL_MODULE_SUFFIX := $(TARGET_EXECUTABLE_SUFFIX)
endif

include $(BUILD_SYSTEM)/dynamic_binary.mk

ifeq ($(LOCAL_FORCE_STATIC_EXECUTABLE),true)
$(linked_module): $(TARGET_CRTBEGIN_STATIC_O) $(all_objects) $(all_libraries) $(TARGET_CRTEND_O)
	$(transform-o-to-static-executable)
else	
$(linked_module): $(TARGET_CRTBEGIN_DYNAMIC_O) $(all_objects) $(all_libraries) $(TARGET_CRTEND_O)
	$(transform-o-to-executable)
endif
