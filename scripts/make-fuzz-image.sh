#!/bin/bash
set -e

SCRIPT_DIR="$(dirname $0)"
BUILD_DIR="$SCRIPT_DIR/../build"
IMAGE_FILE="$BUILD_DIR/fuzz-app_xen-x86_64.dbg"
SYSMAP_FILE="$BUILD_DIR/fuzz-app_xen-x86_64.System.map"
JSON_FILE="$BUILD_DIR/fuzz-app_xen-x86_64.json"

REMOTE=${1:-root@10.1.0.3}
REMOTE_DIR="/root/fuzz-root/unikraft/apps/fuzz"

DWARF2JSON="/home/$USER/dev/FUZZ/dwarf2json.git/dwarf2json"
if [ ! -f "$DWARF2JSON" ]; then
	echo "Set a valid path for dwarf2json!"
	exit 2
fi

echo "Building $IMAGE_FILE .."
make -j32 -f Makefile.unikraft
[ ! -z $REMOTE ] && scp $IMAGE_FILE $REMOTE:$REMOTE_DIR/$(basename $IMAGE_FILE)

echo "Creating Sysmap file $SYSMAP_FILE.."
export NM=nm
$SCRIPT_DIR/mksysmap $IMAGE_FILE $SYSMAP_FILE

echo "Creating json file $JSON_FILE .."
$DWARF2JSON linux --elf $IMAGE_FILE --system-map $SYSMAP_FILE > $JSON_FILE
[ ! -z $REMOTE ] && scp $JSON_FILE $REMOTE:$REMOTE_DIR/$(basename $JSON_FILE)

