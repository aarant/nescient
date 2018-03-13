#!/bin/bash
set -e -x

pybins=( $1 $2 $3 )

# Compile wheels
for PYBIN in "${pybins[@]}"; do
    "/opt/python/${PYBIN}/bin/pip" wheel /io/ -w wheelhouse/
done

# Audit wheels, to make them into manylinux
for whl in wheelhouse/*.whl; do
    auditwheel repair "$whl" -w /io/dist/
done

# Test wheels
for PYBIN in "${pybins[@]}"; do
    "/opt/python/${PYBIN}/bin/pip" install nose
    "/opt/python/${PYBIN}/bin/pip" install nescient --no-index -f /io/dist/
    (cd /io/dist/; "/opt/python/${PYBIN}/bin/nosetests" nescient -v)
    if [ $? -ne 0 ]; then
        exit $?
    fi
done
