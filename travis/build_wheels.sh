#!/bin/bash
set -e -u -x

pybins=( $1 $2 )

function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping non-platform wheel $wheel"
    else
        auditwheel repair "$wheel" --plat "$PLAT" -w /io/wheelhouse/
    fi
}


# Install a system package required by our library
#yum install -y atlas-devel

# Compile wheels
for PYBIN in "${pybins[@]}"; do
    "/opt/python/${PYBIN}/bin/pip" install -r /io/requirements.txt
    "/opt/python/${PYBIN}/bin/pip" wheel /io/ --no-deps -w wheelhouse/
done

# Bundle external shared libraries into the wheels
for whl in wheelhouse/*.whl; do
    repair_wheel "$whl"
done

# Install packages and test
for PYBIN in "${pybins[@]}"; do
    "/opt/python/${PYBIN}/bin/pip" install nose PyQt5
    "/opt/python/${PYBIN}/bin/pip" install nescient --no-index -f /io/wheelhouse/
    (cd /io/wheelhouse/ && "/opt/python/${PYBIN}/bin/nosetests" nescient -v)
    if [ $? -ne 0 ]; then
        exit $?
    fi
done
