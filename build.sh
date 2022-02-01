#!/bin/bash

FPATH="../mft $(date +'%Y-%m-%d %H-%M-%S')"

mkdir "$FPATH"

header () {
	echo
	echo
	echo "**************************************************************"
	echo "**************************************************************"
	echo "Building $1"
	echo "**************************************************************"
	echo "**************************************************************"
	echo 
	echo 
}


header iOS

xcodebuild archive  -scheme "mft ios" -destination "generic/platform=iOS" \
    -archivePath "${FPATH}/mft_ios"  SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=YES    

if [ $? -ne 0 ]; then
	echo "\n\n******** Error when building for iOS\n\n"
	exit 1
fi

header "iOS Simulator"

xcodebuild archive  -scheme "mft ios" -destination "generic/platform=iOS Simulator" \
    -archivePath "${FPATH}/mft_sim"  SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=YES   

if [ $? -ne 0 ]; then
	echo "\n\n******** Error when building for iOS Simulator\n\n"
	exit 2
fi

header "macOS"
xcodebuild archive  -scheme "mft" -destination "generic/platform=macOS" \
    -archivePath "${FPATH}/mft_macos"  SKIP_INSTALL=NO BUILD_LIBRARY_FOR_DISTRIBUTION=YES 

if [ $? -ne 0 ]; then
	echo "\n\n******** Error when building for macOS\n\n"
	exit 3
fi

header "XCFramework"

xcodebuild -create-xcframework \
   -framework "${FPATH}/mft_ios.xcarchive/Products/Library/Frameworks/mft.framework" \
   -framework "${FPATH}/mft_sim.xcarchive/Products/Library/Frameworks/mft.framework" \
   -framework "${FPATH}/mft_macos.xcarchive/Products/Library/Frameworks/mft.framework" \
   -output "${FPATH}/mft.xcframework"
  
if [ $? -ne 0 ]; then
	echo "\n\n******** Error when building XCFramework\n\n"
	exit 10
fi

echo "\n\nCheck out ${FPATH}"

header "All Done!"


