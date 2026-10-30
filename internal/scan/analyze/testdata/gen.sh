#!/bin/sh
# gen.sh builds the fixtures of the analyze tests into the directory that holds it. It needs Docker,
# and network access for the images and for Alpine's and Fedora's packages.
#
#   elf/                         small ELF files for linux/amd64, built with gcc in Alpine 3.22
#     libbrotlicommon.so.1.0.9   soname libbrotlicommon.so.1
#     libbrotlidec.so.1.0.9      soname libbrotlidec.so.1, needs libbrotlicommon.so.1
#     user                       an executable that needs libbrotlidec.so.1
#     other                      a static executable
#     busybox                    a static executable that Syft's binary classifier recognises
#   apk-installed                the apk database of the apk root
#   syft-apk.json                Syft's JSON for the apk root
#   syft-dpkg.json               Syft's JSON for the dpkg root
#   syft-rpm.json                Syft's JSON for the rpm root
#
# Syft is v1.55.0, JSON schema 16.1.11: the latest stable release when this was written, and the one
# the scanner image pins. Each root is scanned the way the scanner runs Syft:
#
#   SYFT_CHECK_FOR_APP_UPDATE=false syft scan dir:<root> -o syft-json --quiet
#
# The tests build the same roots in a temporary directory (analyze_test.go), but for the databases of
# dpkg and rpm, which the analysis reads only through Syft's JSON. Syft reads only the package
# databases, /etc/os-release and the busybox banner from the roots.
#
# Running it again gives the same files, but for the digests of the rpm database in the top-level
# "files" of syft-rpm.json: rpm writes the times of the build and of the installation into it.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Each image is pinned by digest. Alpine and Fedora are pinned by their linux/amd64 manifests, so
# that the ELF files and the rpm are the same on any host.
ALPINE=alpine@sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec # alpine:3.22
FEDORA=fedora@sha256:1ad64e0ebefee83263fffacc5cb139b37ff70def215e4fe44720896c83353132 # fedora:43
SYFT=anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a

# --- The ELF files ---------------------------------------------------------------------------------
# They link nothing from a C library and have no build ID, so that they stay small and the same.
mkdir -p "$work/src"
cat >"$work/src/common.c" <<'EOF'
int brotli_common_value(void) { return 1; }
EOF
cat >"$work/src/dec.c" <<'EOF'
int brotli_common_value(void);
int brotli_decoder_value(void) { return brotli_common_value() + 1; }
EOF
cat >"$work/src/user.c" <<'EOF'
int brotli_decoder_value(void);
void _start(void) { brotli_decoder_value(); for (;;) {} }
EOF
cat >"$work/src/other.c" <<'EOF'
void _start(void) { for (;;) {} }
EOF
cat >"$work/src/busybox.c" <<'EOF'
__attribute__((used)) static const char banner[] = "BusyBox v1.37.0 (2025-01-01 00:00:00 UTC) multi-call binary.";
void _start(void) { for (;;) {} }
EOF
cat >"$work/src/build.sh" <<'EOF'
set -eu
apk add --no-cache gcc musl-dev binutils >/dev/null
gcc --version | head -n 1
cd /src
flags="-Os -nostdlib -fno-asynchronous-unwind-tables -fno-ident -Wl,--build-id=none -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,--hash-style=gnu -s"
gcc $flags -shared -fPIC -Wl,-soname,libbrotlicommon.so.1 -o libbrotlicommon.so.1.0.9 common.c
ln -sf libbrotlicommon.so.1.0.9 libbrotlicommon.so.1
gcc $flags -shared -fPIC -Wl,-soname,libbrotlidec.so.1 -o libbrotlidec.so.1.0.9 dec.c ./libbrotlicommon.so.1.0.9
gcc $flags -Wl,-rpath-link,. -o user user.c ./libbrotlidec.so.1.0.9
gcc $flags -static -o other other.c
gcc $flags -static -o busybox busybox.c
cp libbrotlicommon.so.1.0.9 libbrotlidec.so.1.0.9 user other busybox /out/
EOF
mkdir -p "$here/elf"
docker run --rm --platform linux/amd64 -v "$work/src:/src" -v "$here/elf:/out" "$ALPINE" sh /src/build.sh

# --- The apk root ----------------------------------------------------------------------------------
# brotli-libs owns the libraries and their links. app-tools lists three files, of which only
# /usr/bin/other is present. Nothing owns /usr/bin/user. The binary classifier finds /bin/busybox.
cat >"$here/apk-installed" <<'EOF'
P:brotli-libs
V:1.0.9-r0
A:x86_64
S:2000
I:4096
T:Generic lossless compressor (libraries)
U:https://github.com/google/brotli
L:MIT
o:brotli
m:Example Maintainer <maintainer@example.org>
t:1700000000
c:0000000000000000000000000000000000000000
p:so:libbrotlicommon.so.1=1.0.9 so:libbrotlidec.so.1=1.0.9
F:usr
F:usr/lib
R:libbrotlicommon.so.1
a:0:0:777
R:libbrotlicommon.so.1.0.9
a:0:0:755
R:libbrotlidec.so.1
a:0:0:777
R:libbrotlidec.so.1.0.9
a:0:0:755

P:app-tools
V:1.0.0-r0
A:x86_64
S:1000
I:2048
T:Tools of the fixture image
U:https://example.org/app-tools
L:MIT
o:app-tools
m:Example Maintainer <maintainer@example.org>
t:1700000000
c:0000000000000000000000000000000000000000
F:usr
F:usr/bin
R:other
a:0:0:755
R:gone-a
a:0:0:755
R:gone-b
a:0:0:755

EOF
r="$work/root-apk"
mkdir -p "$r/etc" "$r/lib/apk/db" "$r/usr/lib" "$r/usr/bin" "$r/bin" "$r/app"
printf 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.22.2\nPRETTY_NAME="Alpine Linux v3.22"\n' >"$r/etc/os-release"
printf 'libbrotlicommon.so.1\0/usr/lib/libbrotlicommon.so.1\0libbrotlidec.so.1\0/usr/lib/libbrotlidec.so.1\0' >"$r/etc/ld.so.cache"
cp "$here/apk-installed" "$r/lib/apk/db/installed"
cp "$here/elf/libbrotlicommon.so.1.0.9" "$here/elf/libbrotlidec.so.1.0.9" "$r/usr/lib/"
ln -s libbrotlicommon.so.1.0.9 "$r/usr/lib/libbrotlicommon.so.1"
ln -s libbrotlidec.so.1.0.9 "$r/usr/lib/libbrotlidec.so.1"
cp "$here/elf/user" "$here/elf/other" "$r/usr/bin/"
cp "$here/elf/busybox" "$r/bin/"
printf 'import ctypes.util\nctypes.util.find_library("brotlidec")\n' >"$r/app/load.py"

# --- The dpkg root ---------------------------------------------------------------------------------
# /lib is a link to usr/lib, and the package lists libbrotlidec under /lib, as packages from before
# the move to /usr do. Syft takes the file list from the md5sums file.
r="$work/root-dpkg"
mkdir -p "$r/etc" "$r/var/lib/dpkg/info" "$r/usr/lib/x86_64-linux-gnu"
ln -s usr/lib "$r/lib"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian\n' >"$r/etc/os-release"
cat >"$r/var/lib/dpkg/status" <<'EOF'
Package: libbrotli1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 8
Maintainer: Example Maintainers <maintainers@example.org>
Architecture: amd64
Multi-Arch: same
Source: brotli (1.0.9-2)
Version: 1.0.9-2+b6
Depends: libc6 (>= 2.29)
Description: library implementing brotli encoder and decoder (shared libraries)
 A fixture package of the analyze tests.

EOF
cp "$here/elf/libbrotlicommon.so.1.0.9" "$here/elf/libbrotlidec.so.1.0.9" "$r/usr/lib/x86_64-linux-gnu/"
ln -s libbrotlicommon.so.1.0.9 "$r/usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1"
ln -s libbrotlidec.so.1.0.9 "$r/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1"
docker run --rm --platform linux/amd64 -v "$r:/r" "$ALPINE" sh -euc '
cd /r
{
  md5sum usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1.0.9
  md5sum usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9 | sed "s| usr/lib/| lib/|"
} >"var/lib/dpkg/info/libbrotli1:amd64.md5sums"
'

# --- The rpm root ----------------------------------------------------------------------------------
# rpm installs a package built from the ELF files into an empty root. Syft keeps only the file
# records whose files exist, so the files are installed, not only the database.
r="$work/root-rpm"
mkdir -p "$r/etc"
printf 'NAME="Fedora Linux"\nVERSION="43"\nID=fedora\nVERSION_ID=43\nPRETTY_NAME="Fedora Linux 43"\n' >"$r/etc/os-release"
cat >"$work/src/brotli.spec" <<'EOF'
%global debug_package %{nil}
%global _build_id_links none
%global __os_install_post %{nil}
Name:           brotli
Version:        1.0.9
Release:        1
Summary:        Fixture package of the analyze tests
License:        MIT
URL:            https://example.org/brotli

%description
A fixture package of the analyze tests.

%package -n libbrotli
Summary:        Fixture libraries of the analyze tests

%description -n libbrotli
A fixture package of the analyze tests.

%install
mkdir -p %{buildroot}/usr/lib64
cp /elf/libbrotlicommon.so.1.0.9 /elf/libbrotlidec.so.1.0.9 %{buildroot}/usr/lib64/
ln -s libbrotlicommon.so.1.0.9 %{buildroot}/usr/lib64/libbrotlicommon.so.1
ln -s libbrotlidec.so.1.0.9 %{buildroot}/usr/lib64/libbrotlidec.so.1

%files -n libbrotli
/usr/lib64/libbrotlicommon.so.1
/usr/lib64/libbrotlicommon.so.1.0.9
/usr/lib64/libbrotlidec.so.1
/usr/lib64/libbrotlidec.so.1.0.9
EOF
docker run --rm --platform linux/amd64 -v "$work/src:/src" -v "$here/elf:/elf:ro" -v "$r:/r" "$FEDORA" sh -euc '
dnf -y -q install rpm-build >/dev/null
rpmbuild -bb --quiet --define "_topdir /tmp/rpm" /src/brotli.spec
rpm --root /r --initdb
rpm --root /r -i --nodeps --noscripts /tmp/rpm/RPMS/x86_64/libbrotli-1.0.9-1.x86_64.rpm
'

# --- Syft ------------------------------------------------------------------------------------------
for root in apk dpkg rpm; do
	docker run --rm -e SYFT_CHECK_FOR_APP_UPDATE=false -v "$work/root-$root:/root-$root:ro" "$SYFT" \
		scan "dir:/root-$root" -o syft-json --quiet >"$here/syft-$root.json"
done
