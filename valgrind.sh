#!/bin/sh

rm -f valgrind.log

find tests -maxdepth 1 -type f -executable -exec valgrind --track-origins=yes --leak-check=full -q --log-fd=9 9>>valgrind.log '{}' ';'

if [ -s valgrind.log ]; then
    echo "Valgrind might have detected some bug, see build/valgrind.log"
    exit 1
fi

exit 0