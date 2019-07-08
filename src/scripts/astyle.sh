#!/bin/sh

#Artistic Style Version 3.1


LOG=/dev/null
ASTYLE=/usr/bin/astyle

echo "" > ${LOG}

if [ $# -eq 0 ]
  then echo "No arguments supplied" > ${LOG}
  exit 0
fi

FILE=${1}

${ASTYLE}  -A8 -s4 -N -m0 -n -t4 -H -xT8 -k1 -W1 -p -U -O -o -xC79 -xB -xD ${FILE}


# Mark lines which start with static, struct or enum and end with { or ;
# We don't want them indented
sed -i -e 's/^\(struct.*{$\)/6\1/g' \
       -e 's/^\(struct.*;$\)/6\1/g' \
       -e 's/^\(enum.*{$\)/6\1/g' \
       -e 's/^\(enum.*;$\)/6\1/g' \
       -e 's/^\(static.*{$\)/6\1/g' \
       -e 's/^\(static.*;$\)/6\1/g' \
       ${FILE}


# Remove spaces before tabs, need to test this more

sed -i -e 's/ *\t/\t/g'\
       -e '21,$ s/^\//    \//g' \
       -e '21,$ s/^ \*/     \*/g' \
       -e 's/^\(struct\)/    \1/g' \
       -e 's/^\(enum\)/    \1/g' \
       -e 's/^\(static\)/    \1/g' \
       -e 's/^\(void\)/    \1/g' \
       -e 's/^\(bool.*\)/    \1/gI' \
       -e 's/^\(nk.*\)/    \1/gI' \
       -e 's/^6//g' \
       ${FILE}

