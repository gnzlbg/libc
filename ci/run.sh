#!/usr/bin/env sh

# Builds and runs tests for a particular target passed as an argument to this
# script.

set -ex

TARGET="${1}"

# If we're going to run tests inside of a qemu image, then we don't need any of
# the scripts below. Instead, download the image, prepare a filesystem which has
# the current state of this repository, and then run the image.
#
# It's assume that all images, when run with two disks, will run the `run.sh`
# script from the second which we place inside.
if [ "$QEMU" != "" ]; then
  tmpdir=/tmp/qemu-img-creation
  mkdir -p "${tmpdir}"

  if [ -z "${QEMU#*.gz}" ]; then
    # image is .gz : download and uncompress it
    qemufile="$(echo "${QEMU%.gz}" | sed 's/\//__/g')"
    if [ ! -f "${tmpdir}/${qemufile}" ]; then
      curl --retry 5 "https://s3-us-west-1.amazonaws.com/rust-lang-ci2/libc/${QEMU}" | \
          gunzip -d > "${tmpdir}/${qemufile}"
    fi
  elif [ -z "${QEMU#*.xz}" ]; then
    # image is .xz : download and uncompress it
    qemufile="$(echo "${QEMU%.xz}" | sed 's/\//__/g')"
    if [ ! -f "${tmpdir}/${qemufile}" ]; then
      curl --retry 5 "https://s3-us-west-1.amazonaws.com/rust-lang-ci2/libc/${QEMU}" | \
          unxz > "${tmpdir}/${qemufile}"
    fi
  else
    # plain qcow2 image: just download it
    qemufile="$(echo "${QEMU}" | sed 's/\//__/g')"
    if [ ! -f "${tmpdir}/${qemufile}" ]; then
      curl --retry 5 "https://s3-us-west-1.amazonaws.com/rust-lang-ci2/libc/${QEMU}" \
        > "${tmpdir}/${qemufile}"
    fi
  fi

  # Create a mount a fresh new filesystem image that we'll later pass to QEMU.
  # This will have a `run.sh` script will which use the artifacts inside to run
  # on the host.
  rm -f "${tmpdir}/libc-test.img"
  mkdir "${tmpdir}/mount"

  # Do the standard rigamarole of cross-compiling an executable and then the
  # script to run just executes the binary.
  cargo build \
    --manifest-path libc-test/Cargo.toml \
    --target "${TARGET}" \
    --test main
  rm "${CARGO_TARGET_DIR}/${TARGET}"/debug/main-*.d
  cp "${CARGO_TARGET_DIR}/${TARGET}"/debug/main-* "${tmpdir}"/mount/libc-test
  # shellcheck disable=SC2016
  echo 'exec $1/libc-test' > "${tmpdir}/mount/run.sh"

  du -sh "${tmpdir}/mount"
  genext2fs \
      --root "${tmpdir}/mount" \
      --size-in-blocks 100000 \
      "${tmpdir}/libc-test.img"

  # Pass -snapshot to prevent tampering with the disk images, this helps when
  # running this script in development. The two drives are then passed next,
  # first is the OS and second is the one we just made. Next the network is
  # configured to work (I'm not entirely sure how), and then finally we turn off
  # graphics and redirect the serial console output to out.log.
  qemu-system-x86_64 \
    -m 1024 \
    -snapshot \
    -drive if=virtio,file="${tmpdir}/${qemufile}" \
    -drive if=virtio,file="${tmpdir}/libc-test.img" \
    -net nic,model=virtio \
    -net user \
    -nographic \
    -vga none 2>&1 | tee "${CARGO_TARGET_DIR}/out.log"
  exec egrep "^(PASSED)|(test result: ok)" "${CARGO_TARGET_DIR}/out.log"
fi

command -v cargo

build_types="+nightly +beta +stable +1.13.0 +1.19.0 +1.24.0 +1.30.0"
for build_type in $build_types;
do
    opt=
    if [ "$TARGET" = "x86_64-unknown-linux-gnux32" ]; then
        # FIXME: x86_64-unknown-linux-gnux32 fail to compile without
        # --release
        #
        # See https://github.com/rust-lang/rust/issues/45417
        opt="--release"

        # x86_64-unknown-linux-gnux32 is only available on nightly:
        if [ "$build_type" != "nightly" ]; then
            continue
        fi
    fi

    if [ "$BUILD_ONLY" = "1" ]; then
        cargo "$build_type" build $opt --target "${TARGET}"
    else
        # Building with --no-default-features is currently broken on rumprun
        # because we need cfg(target_vendor), which is currently unstable.
        if [ "$TARGET" != "x86_64-rumprun-netbsd" ]; then
            cargo "$build_type" test $opt \
                  --no-default-features \
                  --manifest-path libc-test/Cargo.toml \
                  --target "${TARGET}"
        fi

        # Test the `extra_traits` feature; requires Rust >= 1.25.0
        if [ "$build_type" != "+1.13.0" ]; then
            cargo "$build_type" test $opt \
                  --features extra_traits \
                  --manifest-path libc-test/Cargo.toml \
                  --target "${TARGET}"
        fi

        cargo "$build_type" test $opt \
             --manifest-path libc-test/Cargo.toml \
             --target "${TARGET}"
    fi
done
