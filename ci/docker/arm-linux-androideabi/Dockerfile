FROM ubuntu:16.04

WORKDIR /android/
COPY android* /android/

RUN sh /android/android-base-apt-get.sh
RUN . /android/android-ndk.sh && \
    download_and_make_toolchain android-ndk-r15c-linux-x86_64.zip arm 14

# Note:
# Do not upgrade to `openjdk-9-jre-headless`, as it will cause certificate error
# when installing the Android SDK (see PR #45193). This is unfortunate, but
# every search result suggested either disabling HTTPS or replacing JDK 9 by
# JDK 8 as the solution (e.g. https://stackoverflow.com/q/41421340). :|
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
  libgl1-mesa-glx \
  libpulse0 \
  libstdc++6:i386 \
  openjdk-8-jre-headless \
  tzdata \
  expect \
  gcc \
  libc6-dev

RUN . /android/android-sdk.sh && \
    download_and_create_avd 4333796 armeabi-v7a 18

ENV PATH=$PATH:/android/sdk/emulator
ENV PATH=$PATH:/android/sdk/tools
ENV PATH=$PATH:/android/sdk/platform-tools

ENV PATH=$PATH:/rust/bin \
    CARGO_TARGET_ARM_LINUX_ANDROIDEABI_LINKER=arm-linux-androideabi-gcc \
    CARGO_TARGET_ARM_LINUX_ANDROIDEABI_RUNNER=/tmp/runtest \
    HOME=/tmp

ENTRYPOINT ["/android/android-start-emulator.sh"]
