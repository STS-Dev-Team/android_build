#!/bin/bash

# (c) Copyright Motorola 2011, All rights reserved.
#   Motorola Confidential Proprietary
#   Contains confidential proprietary information of Motorola, Inc.
#   Reverse engineering is prohibited.
#   The copyright notice does not imply publication.
###################################################################################################
#                       Revision History
###################################################################################################
#
# DATE         AUTHOR     CR NUM            DESCRIPTION
# ====         ======     ======            ======================================================
#
# 09/27/2011   fkw017     IKQCOM-6069       Port from iDEN Android

MAKEFILE_LIST_DIR=out/target/product/$TARGET_PRODUCT
mkdir -p $MAKEFILE_LIST_DIR 2>/dev/null

CKSUM_TMP=`echo $ANDROID_BUILD_TOP | wc -m`
CKSUM_PATH=`pwd | cut -c $CKSUM_TMP`
CKSUM_PARAMS="$CKSUM_PATH $*"
CKSUM=`echo "$CKSUM_PARAMS" | cksum | sed s/" "//`

FILE_TYPE_TO_CACHE=`echo "$*" | grep -o -G " [^' ']*$" | sed s/" "//`

MAKEFILE_LIST=$MAKEFILE_LIST_DIR/$FILE_TYPE_TO_CACHE"."$CKSUM".cache"

# Logic:
# 1) Check for existence of local cache file for this build
# 2) If there is no server cache, need to do full scan of tree
if [ -e $MAKEFILE_LIST ]
then
    echo "INFO: Using cached list of $FILE_TYPE_TO_CACHE files to speed up build."  1>&2
    echo "INFO: Cache location: $MAKEFILE_LIST" 1>&2
else
    echo "INFO: $FILE_TYPE_TO_CACHE cache list is out of date. Regenerating..."  1>&2
    echo "build/tools/findleaves.py $* $MAKEFILE_LIST" 1>&2
    build/tools/findleaves.py $* > $MAKEFILE_LIST
    echo "INFO: Done regenerating $FILE_TYPE_TO_CACHE cache list."  1>&2
fi

cat $MAKEFILE_LIST

exit 0
