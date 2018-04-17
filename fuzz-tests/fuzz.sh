#!/bin/bash

harden_build_dir="build_afl_harden"
asan_build_dir="build_afl_asan"
debug_build_dir="build_debug"
testcases_dir="input"

valid_targets=(`ls -Sr fuzz_*.c | cut -d'.' -f1`)
output_dir=""
input_dir=""
target=${valid_targets[0]}
mode="asan"
num_cores=4
fuzz_args=""
masterFuzzer=""
valid_target=0


build_targets() {
    export AFL_HARDEN=1 && \
    mkdir -p $harden_build_dir && \
    cd $harden_build_dir && \
    cmake \
        -DCMAKE_CXX_COMPILER=afl-g++ \
        -DCMAKE_C_COMPILER=afl-gcc \
        -DCMAKE_C_FLAGS="-O9 -std=c99 -Wall -Wextra -Wpedantic -Werror" .. && \
    make -j && \
    cd .. && \
    unset AFL_HARDEN && \
    export AFL_USE_ASAN=1 && \
    mkdir -p $asan_build_dir && \
    cd $asan_build_dir && \
    cmake \
        -DCMAKE_CXX_COMPILER=afl-g++ \
        -DCMAKE_C_COMPILER=afl-gcc \
        -DCMAKE_C_FLAGS="-O9 -std=c99 -Wall -Wextra -Wpedantic -Werror -m32" .. && \
    make -j && \
    unset AFL_USE_ASAN && \
    cd .. && \
    mkdir -p $debug_build_dir && \
    cd $debug_build_dir && \
    cmake \
        -DCMAKE_C_FLAGS="-O0 -g -ggdb -std=c99 -Wall -Wextra -Wpedantic -Werror -fprofile-arcs -ftest-coverage" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage" \
        -DUSE_SANITIZERS=ON .. && \
    make -j && cd .. && return 0 || return 1
}



print_help() {
    echo "Usage: $0 target (asan|harden) numCores"
    echo "Valid targets are:"
    for v in $valid_targets; do
        echo "   $v"
    done
}

if ! build_targets > /dev/null; then
    echo "Error: Building of binaries failed."
    exit 1
fi

check_and_set_config() {

    valid_target=0

    for v in "${valid_targets[@]}"; do
        if [ "$v" = "$target" ]; then
            valid_target=1
            break
        fi
    done

    if [ $valid_target -eq "0" ]; then
        echo "Error: \"$target\" is not a valid target."
        print_help
        return 1
    fi


    input_dir="$testcases_dir/$target"

    if ! [ `find $input_dir -type f | wc -l` -gt 0 ]; then
        echo "Error: No valid testcases in $input_dir"
        return 1
    fi

    output_dir="output/$target"

    if [ "$mode" = "asan" ]; then
        binary_dir=$asan_build_dir
        mode="asan"
        fuzz_args="-m none"
    elif [ "$mode" = "harden" ]; then
        binary_dir=$harden_build_dir
        mode="harden"
    else
        echo "Error: \"$mode\" not a valid method."
        print_help
        return 1
    fi

    mkdir -p $output_dir

    if ! [ $num_cores -ge 0 2>/dev/null ]; then
        echo "Error: \"$num_cores\" not a valid number of cores."
        print_help
    fi

    if ! find $binary_dir -type f -executable -name $target > /dev/null; then
        echo "Error: Binary target does not exist, why not?"
    fi


    masterFuzzer="1Master$mode$target"
    return 0
}


select_target() {
    while true; do
        echo "Select target:
        "

        i=1
        for v in "${valid_targets[@]}"; do
            echo "    [$i] $v"
            ((i++))
        done

        read -p "    
    Select: " choice

        ((choice--))

        target=${valid_targets[choice]}

        if check_and_set_config; then
            return 0
        fi

    done

}

set_num_cores() {
    while true; do

        read -p "    
    Select num cores [1-N]: " num_cores

        if check_and_set_config; then
            return 0
        fi

    done
}

select_mode() {
    while true; do
    read -p "Select mode:

    [1] asan
    [2] harden

    Select: " m
    case $m in
        [1]* ) mode="asan"; break;;
        [2]* ) mode="harden"; break;;
        * ) echo "Please select harden or asan";;
    esac
    done
    
    check_and_set_config

}

do_start_fuzz() {
    screen -dmS $masterFuzzer afl-fuzz $fuzz_args -i $input_dir -o $output_dir -M fuzzer1 -- ./$binary_dir/$target
    sleep 1

    if ! screen -list | grep -q $masterFuzzer; then
        echo "Error: Master fuzzing start failed."
        afl-fuzz $fuzz_args -i $input_dir -o $output_dir -M fuzzer1 -- ./$binary_dir/$target
        echo "Initial fuzzing failed."
        return 1
    fi

    for a in $(seq 2 $num_cores); do
        slaveFuzzer=$a"Slave$mode$target"
        screen -dmS $slaveFuzzer afl-fuzz $fuzz_args -i $input_dir -o $output_dir -S fuzzer$a -- ./$binary_dir/$target
    done

    screen -x $masterFuzzer

    for a in $(seq 2 $num_cores); do
        slaveFuzzer=$a"Slave$mode$target"
        screen -x $slaveFuzzer -X stuff "^C"
    done

    mkdir -p $output_dir/queue_all

    for a in $(seq 1 $num_cores); do
        if [ -d $output_dir/fuzzer$a/queue ]; then
            mkdir -p $output_dir/queue_all
            cp $output_dir/fuzzer$a/queue/* $output_dir/queue_all/ > /dev/null 2>&1
        fi
    done

    echo "Initial fuzzing done."

    return 0

}

do_cmin() {

    if ! [ -d $output_dir/queue_all ]; then
        echo "No output dir detected, please start fuzz"
        return 1
    fi

    afl-cmin $fuzz_args -i $output_dir/queue_all -o $output_dir/queue_cmin -- ./$binary_dir/$target

    echo "afl-cmin process done."

}

do_tmin() {

    if ! [ -d $output_dir/queue_cmin ]; then
        echo "No cmin output dir detected, please start fuzz"
        return 1
    fi

    total=`ls $output_dir/queue_cmin | wc -l`
    mkdir -p $output_dir/queue_tmin

    for k in `seq 1 $num_cores $total`
    do
      for i in `seq 0 $(expr $num_cores - 1)`
      do
        #echo "ls -Sr $output_dir/queue_cmin | sed $(expr $i + $k)\"q;d\""
        file=`ls -Sr $output_dir/queue_cmin | sed $(expr $i + $k)"q;d"`
        if [ -f $output_dir/queue_cmin/$file ]; then
            afl-tmin -m none -i $output_dir/queue_cmin/$file -o $output_dir/queue_tmin/$file -- ./$binary_dir/$target &
        fi
      done
      wait
    done

    rm -rf $output_dir/fuzzer*/queue
    for a in $(seq 1 $num_cores); do
        cp -r $output_dir/queue_tmin $output_dir/fuzzer$a/queue
    done
    echo "afl-tmin process done."
}

do_continue_fuzz() {

    if ! [ -d $output_dir/queue_all ]; then
        echo "No output dir detected, please start fuzz"
        return 1
    fi

    screen -dmS $masterFuzzer afl-fuzz $fuzz_args -i- -o $output_dir -M fuzzer1 -- ./$binary_dir/$target
    sleep 1

    if ! screen -list | grep -q $masterFuzzer; then
        echo "Error: Master fuzzing start failed."
        afl-fuzz $fuzz_args -i- -o $output_dir -M fuzzer1 -- ./$binary_dir/$target
        exit 1
    fi

    for a in $(seq 2 $num_cores); do
        slaveFuzzer=$a"Slave$mode$target"
        indir="-"
        if ! [ -d $output_dir/fuzzer$a ]; then
            indir=$input_dir
        fi
        screen -dmS $slaveFuzzer afl-fuzz $fuzz_args -i$indir -o $output_dir -S fuzzer$a -- ./$binary_dir/$target
    done

    screen -x $masterFuzzer

    for a in $(seq 1 $num_cores); do
        if [ -d $output_dir/fuzzer$a/queue ]; then
            mkdir -p $output_dir/queue_all
            cp $output_dir/fuzzer$a/queue/* $output_dir/queue_all/ > /dev/null 2>&1
        fi
    done

}

do_copy_output() {

    source_dir=""

    while true; do 

        read -p "
    What files do you want to copy to input?
    Only inputs resulting in return code 0 will be copied.

    [1] Raw output from afl-fuzz
    [2] Output from afl-cmin and afl-tmin
    [0] Quit

    Select: " yn
        case $yn in
            [1]* ) source_dir=$output_dir/queue_all;;
            [2]* ) source_dir=$output_dir/queue_tmin;;
            [0]* ) return 0;;
            * ) echo "Please answer yes or no.";;
        esac

        if ! [ -d $source_dir ]; then
            echo "No source dir detected, please check configuration."
        else
            break
        fi

    done

    for file in `find $source_dir -type f`; do
        if ./$debug_build_dir/$target < $file > /dev/null ; then
            mdname=$(md5sum $file | awk '{print $1}')
            echo "Copying file $file to name $mdname"
            cp -f $file $input_dir/$mdname
        fi
    done

}

do_reset() {
    rm -rf $output_dir
    mkdir -p $output_dir
    echo "$output_dir deleted" 
}

do_dry_run() {
    find $output_dir -type f -exec sh -c "cat {} | ./$debug_build_dir/$target > /dev/null && echo \"Return with 0: {}\"" \;
    lcov --base-directory $debug_build_dir --directory $debug_build_dir --capture --output-file $debug_build_dir/coverage.info
    genhtml -o $debug_build_dir/coverage_report $debug_build_dir/coverage.info
    echo "Coverage report in $(pwd)/$debug_build_dir/coverage_report/index.html"
}

main_menu() {

    check_and_set_config

    while true; do 

        read -p "Salt-channel-c Fuzzing tool

    [1] Select target [$target]
    [2] Select mode [$mode]
    [3] Select num cores [$num_cores]
    [4] Start fuzz (Press CTRL+C to break)
    [5] cmin and tmin
    [6] Continue fuzz (Press CTRL+C to break)
    [7] Copy output to input
    [8] Reset
    [9] Dry run with coverage
    [0] Quit

    Select: " yn
        case $yn in
            [1]* ) select_target;;
            [2]* ) select_mode;;
            [3]* ) set_num_cores;;
            [4]* ) do_start_fuzz;;
            [5]* ) do_cmin && do_tmin;;
            [6]* ) do_continue_fuzz;;
            [7]* ) do_copy_output;;
            [8]* ) do_reset;;
            [9]* ) do_dry_run;;
            [0]* ) return 0;;
            * ) echo "Please answer yes or no.";;
        esac

    done
}

main_menu
