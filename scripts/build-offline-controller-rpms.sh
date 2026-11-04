#!/usr/bin/env bash
# Collect an x86_64 RHEL 9 controller RPM repository on a connected Docker host.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: bash scripts/build-offline-controller-rpms.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi

ubi_image=registry.access.redhat.com/ubi9/ubi@sha256:8f989cc9270da6abec0144c22846ed1e6e92e462dc7768ce0981c4ac1d574733
metadata_image=ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
mkdir -p -- "$(dirname -- "$1")"
output="$(cd -- "$(dirname -- "$1")" && pwd -P)/$(basename -- "$1")"
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "Choose an unused output directory." >&2
    exit 2
fi
staging=$(mktemp -d "$(dirname -- "$output")/.prthak-rpm-build.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT

# Keep the resolver's RPM database empty so the output includes dependencies
# that happen to be installed in the builder, too. Enable only public sources.
docker run --rm -i --platform linux/amd64 --entrypoint /bin/bash "$ubi_image" -s <<'COLLECT' | tar -xf - -C "$staging"
set -euo pipefail
export LC_ALL=C
mkdir -p /media/rpms /media/keys
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --max-time 120 --max-filesize 262144 \
    --output /media/keys/docker.asc https://download.docker.com/linux/rhel/gpg

key_home=$(mktemp -d)
gpg --no-options --batch --no-autostart --homedir "$key_home" --with-colons \
    --show-keys --fingerprint /media/keys/docker.asc > "$key_home/key.txt"
primary_fingerprint=$(awk -F: '
    $1 == "pub" { primary = 1; count++ }
    $1 == "fpr" && primary { print $10; primary = 0 }
    END { if (count != 1 || primary) exit 1 }
' "$key_home/key.txt")
if [ "$primary_fingerprint" != 060A61C51B558A7F742B77AAC52FEB6B621E9F35 ]; then
    echo "Docker RPM signing key fingerprint did not verify." >&2
    exit 1
fi

dnf --noplugins --releasever=9 --installroot=/tmp/prthak-resolve \
    --disablerepo='*' --enablerepo=ubi-9-baseos-rpms --enablerepo=ubi-9-appstream-rpms \
    --repofrompath=prthak-docker,https://download.docker.com/linux/rhel/9/x86_64/stable \
    --enablerepo=prthak-docker --setopt=install_weak_deps=False \
    --setopt=ubi-9-baseos-rpms.gpgcheck=1 --setopt=ubi-9-appstream-rpms.gpgcheck=1 \
    --setopt=prthak-docker.gpgcheck=1 --setopt=prthak-docker.gpgkey=file:///media/keys/docker.asc \
    --downloadonly --downloaddir=/media/rpms -y install \
    python3 ca-certificates shadow-utils tar \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >&2
tar -C /media -cf - keys rpms
COLLECT

# The Ubuntu container supplies only the repository indexing tool. The package
# bytes come exclusively from the signed Red Hat and Docker RPM repositories.
docker run --rm -i --mount "type=bind,src=$staging/rpms,dst=/packages,readonly" \
    --entrypoint /bin/bash "$metadata_image" -s <<'INDEX' | tar -xf - -C "$staging/rpms"
set -euo pipefail
apt-get update -qq >&2
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends createrepo-c >&2
mkdir /metadata
createrepo_c --no-database --outputdir /metadata /packages >&2
tar -C /metadata -cf - repodata
INDEX

test -s "$staging/rpms/repodata/repomd.xml"
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "The output directory appeared during the build." >&2
    exit 2
fi
mv -- "$staging" "$output"
echo "Prepared offline RPM repository at $output/rpms"
