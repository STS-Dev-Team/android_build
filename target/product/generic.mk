#
# Copyright (C) 2007 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This is a generic phone product that isn't specialized for a specific device.
# It includes the base Android platform.

$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_no_telephony.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony.mk)

# Overrides
PRODUCT_BRAND := generic
PRODUCT_DEVICE := generic
PRODUCT_NAME := generic

# BEGIN MOT GB UPMERGE, a18772, 01/19/2011
# BEGIN Motorola, pwn687.   Update the supported locale IKMAIN-502
PRODUCT_LOCALES := \
        en_US \
        es_US
# END Motorola

# BEGIN Motorola, jnp847, Feb-7-2010, IKMAP-5000
# Product Packages Support for User and Eng Builds
-include vendor/moto/common/common-phone.mk
# END IKMAP-5000

# BEGIN IKSTABLETWO-2308
ifeq ($(TARGET_PRODUCT),generic)
  PRODUCT_LOCALES += ldpi mdpi hdpi xhdpi
endif 
# END IKSTABLETWO-2308
# END MOT GB UPMERGE, a18772, 01/19/2010
