###########################################################
## Standard rules for building a java library.
##
###########################################################

ifdef LOCAL_IS_HOST_MODULE
$(error $(LOCAL_PATH): Host java libraries must use BUILD_HOST_JAVA_LIBRARY)
endif

# BEGIN MOT GB UPMERGE, a18772, 12/24/2010
# Motorola, a19677, 11/18/09, addon support for Android.mk when building
# java libraries.
ifeq ($(shell stat motorola/$(LOCAL_PATH)/AndroidAppend.mk 2>&1 >/dev/null),)
$(warning including motorola/$(LOCAL_PATH)/AndroidAppend.mk)
include motorola/$(LOCAL_PATH)/AndroidAppend.mk
endif
# End Motorola
# END MOT GB UPMERGE, a18772, 12/24/2010

LOCAL_MODULE_SUFFIX := $(COMMON_JAVA_PACKAGE_SUFFIX)
LOCAL_MODULE_CLASS := JAVA_LIBRARIES

ifneq (,$(LOCAL_ASSET_DIR))
$(error $(LOCAL_PATH): Target java libraries may not set LOCAL_ASSET_DIR)
endif

ifneq (,$(LOCAL_RESOURCE_DIR))
$(error $(LOCAL_PATH): Target java libraries may not set LOCAL_RESOURCE_DIR)
endif

#xxx base_rules.mk looks at this
all_res_assets :=

LOCAL_BUILT_MODULE_STEM := javalib.jar

intermediates.COMMON := $(call local-intermediates-dir,COMMON)

# This file will be the one that other modules should depend on.
common_javalib.jar := $(intermediates.COMMON)/$(LOCAL_BUILT_MODULE_STEM)
LOCAL_INTERMEDIATE_TARGETS += $(common_javalib.jar)

ifneq (true,$(WITH_DEXPREOPT))
LOCAL_DEX_PREOPT :=
else
ifeq (,$(TARGET_BUILD_APPS))
ifndef LOCAL_DEX_PREOPT
LOCAL_DEX_PREOPT := true
endif
endif
endif
ifeq (false,$(LOCAL_DEX_PREOPT))
LOCAL_DEX_PREOPT :=
endif

#################################
include $(BUILD_SYSTEM)/java.mk
#################################

ifeq ($(LOCAL_IS_STATIC_JAVA_LIBRARY),true)
# No dex; all we want are the .class files with resources.
$(common_javalib.jar) : $(full_classes_jar) $(java_resource_sources)
	@echo "target Static Jar: $(PRIVATE_MODULE) ($@)"
	$(copy-file-to-target)
ifneq ($(extra_jar_args),)
	$(add-java-resources-to-package)
endif

$(LOCAL_BUILT_MODULE): $(common_javalib.jar)
	$(copy-file-to-target)

else # !LOCAL_IS_STATIC_JAVA_LIBRARY

$(common_javalib.jar): PRIVATE_DEX_FILE := $(built_dex)
$(common_javalib.jar) : $(built_dex) $(java_resource_sources) | $(AAPT)
	@echo "target Jar: $(PRIVATE_MODULE) ($@)"
	$(create-empty-package)
	$(add-dex-to-package)
ifneq ($(extra_jar_args),)
	$(add-java-resources-to-package)
endif

# BEGIN Motorola, a5705c, 01/06/2012, IKHSS7-2666
# Workaround to split big jar into two jar files
ifeq ($(LOCAL_DEX_WORKAROUND),true)
common_javalib.jar_ext := $(addsuffix -ext.jar,$(basename $(common_javalib.jar)))
$(common_javalib.jar_ext): PRIVATE_DEX_FILE := $(built_dex_ext)
$(common_javalib.jar_ext) : $(common_javalib.jar) $(built_dex_ext) $(java_resource_sources) | $(AAPT)
	@echo "target Jar: $(PRIVATE_MODULE) ($@)"
	$(create-empty-package)
	$(add-dex-to-package)

built_javalib_ext := $(basename $(LOCAL_BUILT_MODULE))-ext.jar
$(built_javalib_ext): $(common_javalib.jar_ext) | $(ACP)
	$(call copy-file-to-target)
$(LOCAL_BUILT_MODULE) : $(built_javalib_ext)
endif
# END IKHSS7-2666

ifdef LOCAL_DEX_PREOPT
dexpreopt_boot_jar_module := $(filter $(LOCAL_MODULE),$(DEXPREOPT_BOOT_JARS_MODULES))
ifneq ($(dexpreopt_boot_jar_module),)
# boot jar's rules are defined in dex_preopt.mk
dexpreopted_boot_jar := $(DEXPREOPT_BOOT_JAR_DIR_FULL_PATH)/$(dexpreopt_boot_jar_module)_nodex.jar

# BEGIN Motorola, a5705c, 01/06/2012, IKHSS7-2666
# Workaround to split big jar into two jar files
ifeq ($(LOCAL_DEX_WORKAROUND),true)
dexpreopted_boot_jar_ext := $(addsuffix -ext.jar,$(basename $(dexpreopted_boot_jar)))
built_dexpreopted_boot_jar_ext := $(addsuffix -ext.jar,$(basename $(built_dexpreopted_boot_jar)))
$(LOCAL_BUILT_MODULE): $(built_dexpreopted_boot_jar_ext)
$(built_dexpreopted_boot_jar_ext): $(dexpreopted_boot_jar_ext) | $(ACP)
	$(call copy-file-to-target)
endif
# END IKHSS7-2666

$(LOCAL_BUILT_MODULE) : $(dexpreopted_boot_jar) | $(ACP)
	$(call copy-file-to-target)

dexpreopted_boot_odex := $(DEXPREOPT_BOOT_JAR_DIR_FULL_PATH)/$(dexpreopt_boot_jar_module).odex
built_odex := $(basename $(LOCAL_BUILT_MODULE)).odex
$(built_odex) : $(dexpreopted_boot_odex) | $(ACP)
	$(call copy-file-to-target)

# BEGIN Motorola, a5705c, 01/06/2012, IKHSS7-2666
# Workaround to split big jar into two jar files
ifeq ($(LOCAL_DEX_WORKAROUND),true)
dexpreopted_boot_odex_ext := $(addsuffix -ext.odex,$(basename $(dexpreopted_boot_odex)))
built_odex_ext := $(addsuffix -ext.odex,$(basename $(built_odex)))
$(built_odex_ext) : $(dexpreopted_boot_odex_ext) | $(ACP)
	$(call copy-file-to-target)
endif
# END IKHSS7-2666

else # dexpreopt_boot_jar_module
built_odex := $(basename $(LOCAL_BUILT_MODULE)).odex
$(built_odex): PRIVATE_MODULE := $(LOCAL_MODULE)
# Make sure the boot jars get dex-preopt-ed first
$(built_odex) : $(DEXPREOPT_BOOT_ODEXS)
$(built_odex) : $(common_javalib.jar) | $(DEXPREOPT) $(DEXOPT)
	@echo "Dexpreopt Jar: $(PRIVATE_MODULE) ($@)"
	$(hide) rm -f $@
	$(call dexpreopt-one-file,$<,$@)

$(LOCAL_BUILT_MODULE) : $(common_javalib.jar) | $(ACP) $(AAPT)
	$(call copy-file-to-target)
ifneq (nostripping,$(LOCAL_DEX_PREOPT))
	$(call dexpreopt-remove-classes.dex,$@)
endif

endif # dexpreopt_boot_jar_module

else # LOCAL_DEX_PREOPT

$(LOCAL_BUILT_MODULE) : $(common_javalib.jar) | $(ACP)
	$(call copy-file-to-target)

endif # LOCAL_DEX_PREOPT
endif # !LOCAL_IS_STATIC_JAVA_LIBRARY
