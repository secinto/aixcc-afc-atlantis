#!/bin/bash
# Make fuzzer directory
PROJECT_DIR=$SRC/cp-c-swftools-src
CCFLAG="$CC $CFLAGS"
export CC=$CCFLAG
export CFLAGS=""

build() {
pushd .
    cd $PROJECT_DIR
    # [ -d .git ] && git reset --hard && git clean -xdf
    # ./autogen.sh
    ./configure
    make
popd
}

build_libfuzzer() {
pushd .
    cd $PROJECT_DIR
    mkdir fuzz
    cp $SRC/fuzz_* fuzz/
    cd $PROJECT_DIR
    $CC -std=c17 -DHAVE_CONFIG_H -o fuzz_swfdump fuzz/fuzz_swfdump.c $LIB_FUZZING_ENGINE lib/librfxswf.a lib/libbase.a -I fuzz -lz
    cp fuzz_swfdump $OUT/
popd
}


build
build_libfuzzer # libfuzzer only
cp $SRC/fuzz_*.options $OUT/
