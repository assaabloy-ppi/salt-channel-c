#!/bin/sh
REPORT_DIR="html"

SCAN_OPT="-enable-checker alpha.core.BoolAssignment \
-enable-checker alpha.core.CastSize \
-enable-checker alpha.core.DynamicTypeChecker \
-enable-checker alpha.core.FixedAddr \
-enable-checker alpha.core.IdenticalExpr \
-enable-checker alpha.core.PointerArithm \
-enable-checker alpha.core.PointerSub \
-enable-checker alpha.core.SizeofPtr \
-enable-checker alpha.core.TestAfterDivZero \
-enable-checker alpha.deadcode.UnreachableCode \
-enable-checker alpha.security.ArrayBoundV2 \
-enable-checker alpha.security.MallocOverflow \
-enable-checker alpha.security.ReturnPtrRange \
-enable-checker alpha.unix.PthreadLock \
-enable-checker alpha.unix.Stream \
-enable-checker alpha.unix.cstring.BufferOverlap \
-enable-checker alpha.unix.cstring.NotNullTerminated \
-enable-checker alpha.unix.cstring.OutOfBounds \
-enable-checker nullability.NullableDereferenced \
-enable-checker optin.performance.Padding \
-enable-checker security.insecureAPI.rand \
-enable-checker security.insecureAPI.strcpy"

# \
# --analyzer-target=arm-none-eabi"

# find / -name 'scan-build'
# /usr/share/clang/scan-build-6.0/share/scan-build
# /usr/share/clang/scan-build-6.0/bin/scan-build
# /usr/share/clang/scan-build-py-6.0/bin/scan-build
# /usr/lib/llvm-6.0/share/scan-build
# /usr/lib/llvm-6.0/bin/scan-build

# find / -name 'ccc-analyzer'
# /usr/share/clang/scan-build-6.0/libexec/ccc-analyzer
# /usr/lib/llvm-6.0/libexec/ccc-analyzer

# find / -name 'c++-analyzer'
# /usr/share/clang/scan-build-6.0/libexec/c++-analyzer
# /usr/lib/llvm-6.0/libexec/c++-analyzer

SCAN_BUILD="/usr/share/clang/scan-build-6.0/bin/scan-build"
CCC_ANALYZER="/usr/lib/llvm-6.0/libexec/ccc-analyzer"
CXX_ANALYZER="/usr/lib/llvm-6.0/libexec/c++-analyzer"

mkdir -p Debug
cd Debug
$SCAN_BUILD -v -o $REPORT_DIR $SCAN_OPT cmake -DCMAKE_CXX_COMPILER=$CXX_ANALYZER -DCMAKE_C_COMPILER=$CCC_ANALYZER ..
make -j cmocka
make clean
make tweetnacl_modified
$SCAN_BUILD -v -o $REPORT_DIR $SCAN_OPT make -j
