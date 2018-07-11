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
    -enable-checker alpha.core.Conversion \
    -enable-checker alpha.security.taint.TaintPropagation \
    -enable-checker alpha.unix.BlockInCriticalSection \
    -enable-checker optin.portability.UnixAPI \
    -enable-checker valist.CopyToSelf \
    -enable-checker valist.Uninitialized \
    -enable-checker valist.Unterminated \
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
    -enable-checker security.insecureAPI.strcpy \
    -enable-checker security.FloatLoopCounter -maxloop 100"


SCAN_BUILD=$(find /usr -type f -executable -name scan-build | sort | tail -1)
CCC_ANALYZER=$(find /usr -type f -executable -name ccc-analyzer | sort | tail -1)
CXX_ANALYZER=$(find /usr -type f -executable -name c++-analyzer | sort | tail -1)

mkdir -p Debug
cd Debug
$SCAN_BUILD -v -o $REPORT_DIR $SCAN_OPT cmake -DCMAKE_CXX_COMPILER=$CXX_ANALYZER -DCMAKE_C_COMPILER=$CCC_ANALYZER ..
make -j cmocka
make clean
make tweetnacl_modified
$SCAN_BUILD -v -o $REPORT_DIR $SCAN_OPT make -j
