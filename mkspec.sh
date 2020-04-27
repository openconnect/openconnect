#!/bin/bash

TARGET="$1"

GITCOMMIT="$(git rev-parse HEAD)"
GITDESC="$(git describe --tags HEAD)"

GITTAG="$(echo $GITDESC | cut -f1 -d-)"
GITTAG="${GITTAG#v}"

if [ "v$GITTAG" = "$GITDESC" ]; then
    ISSNAP=0
    GITCOUNT=0
else
    ISSNAP=1
    GITCOUNT="$(echo $GITDESC | cut -f2 -d-)"
fi

sed -e "s/@ISSNAP@/${ISSNAP}/" \
    -e "s/@VERSION@/${GITTAG}/" \
    -e "s/@SNAPCOMMIT@/${GITCOMMIT}/" \
    -e "s/@SNAPCOUNT@/${GITCOUNT}/" \
    ${TARGET}.spec.in > ${TARGET}.spec
