#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

# Verifpal release driver.
#
#   scripts/release.sh [--dry-run] [--local] [VERSION]
#
# By default this script is a *gate and a tagger*: it proves the tree is
# releasable, bumps the version, and pushes the tag. Pushing the tag is what
# starts .github/workflows/release.yml, which runs goreleaser and publishes.
# --local runs the publish here instead, for when CI is not an option.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DRY_RUN=0
LOCAL_PUBLISH=0
VERSION=""

for arg in "$@"; do
	case "${arg}" in
		--dry-run) DRY_RUN=1 ;;
		--local) LOCAL_PUBLISH=1 ;;
		-h|--help)
			sed -n '6,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
			exit 0
			;;
		-*)
			echo "[Verifpal] Unknown option: ${arg}" >&2
			exit 1
			;;
		*) VERSION="${arg}" ;;
	esac
done

say() { echo "[Verifpal] $*"; }
die() { echo "[Verifpal] error: $*" >&2; exit 1; }

run() {
	if [[ "${DRY_RUN}" -eq 1 ]]; then
		echo "[Verifpal] (dry run) $*"
		return 0
	fi
	"$@"
}

# ---------------------------------------------------------------- preflight

for tool in git cargo goreleaser make curl; do
	command -v "${tool}" >/dev/null 2>&1 || die "${tool} is not on PATH."
done

if [[ "$OSTYPE" == "darwin"* ]]; then
	SED=gsed
	command -v gsed >/dev/null 2>&1 || die "gsed is not on PATH (brew install gnu-sed)."
else
	SED=sed
fi

[[ -f Cargo.toml && -f .goreleaser.yml ]] || die "run this from the Verifpal repository."

if [[ "${DRY_RUN}" -eq 0 && "${LOCAL_PUBLISH}" -eq 1 && -z "${GITHUB_TOKEN:-}" ]]; then
	die "GITHUB_TOKEN is unset, and --local publishes with goreleaser from here. Export a token, or drop --local and let CI publish."
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "${BRANCH}" == "master" ]] || die "on branch '${BRANCH}'; releases are cut from master."

# A dirty tree would otherwise be swept wholesale into the release commit.
if ! git diff-index --quiet HEAD -- || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
	git status --short >&2
	die "working tree is not clean. Commit, stash or clean the changes above first."
fi

if [[ "${DRY_RUN}" -eq 0 ]]; then
	git fetch --quiet origin "${BRANCH}" --tags
	LOCAL_HEAD="$(git rev-parse HEAD)"
	REMOTE_HEAD="$(git rev-parse "origin/${BRANCH}")"
	[[ "${LOCAL_HEAD}" == "${REMOTE_HEAD}" ]] || die "local ${BRANCH} and origin/${BRANCH} have diverged. Pull or push first."
fi

# ------------------------------------------------------------------ version

CURRENT_VERSION="$(grep -m1 '^version = ' Cargo.toml | ${SED} 's/.*"\(.*\)"/\1/')"
say "current version is ${CURRENT_VERSION}."

if [[ -z "${VERSION}" ]]; then
	read -r -p "[Verifpal] Enter version: " VERSION
fi

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
	|| die "'${VERSION}' is not a MAJOR.MINOR.PATCH version."

version_is_newer() {
	local candidate="$1" current="$2"
	[[ "${candidate}" != "${current}" ]] \
		&& [[ "$(printf '%s\n%s\n' "${current}" "${candidate}" | sort -V | tail -1)" == "${candidate}" ]]
}

version_is_newer "${VERSION}" "${CURRENT_VERSION}" \
	|| die "${VERSION} is not strictly newer than ${CURRENT_VERSION}."

TAG="v${VERSION}"
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null && die "tag ${TAG} already exists locally."
if [[ "${DRY_RUN}" -eq 0 ]] && git ls-remote --exit-code --tags origin "${TAG}" >/dev/null 2>&1; then
	die "tag ${TAG} already exists on origin."
fi

say "releasing ${CURRENT_VERSION} -> ${VERSION}."

# --------------------------------------------------------------- test gate

say "running the full test battery before anything is written."
make lint
make test
make test-exhaustive

# ------------------------------------------------------------ release notes

NOTES_FILE="assets/releasenotes.txt"

if [[ "${DRY_RUN}" -eq 1 ]]; then
	say "(dry run) leaving ${NOTES_FILE} untouched."
else
	PREVIOUS_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
	NOTES_BACKUP="$(mktemp)"
	cp "${NOTES_FILE}" "${NOTES_BACKUP}"
	{
		echo "Verifpal ${VERSION}"
		echo
		if [[ -n "${PREVIOUS_TAG}" ]]; then
			echo "Changes since ${PREVIOUS_TAG}:"
			echo
			git log --no-merges --pretty='- %s' "${PREVIOUS_TAG}..HEAD"
		fi
		echo
		echo "--- Previous release notes, for reference; delete this block before saving. ---"
		echo
		cat "${NOTES_BACKUP}"
	} > "${NOTES_FILE}"

	"${EDITOR:-vi}" "${NOTES_FILE}"

	if grep -q '^--- Previous release notes' "${NOTES_FILE}"; then
		cp "${NOTES_BACKUP}" "${NOTES_FILE}"
		rm -f "${NOTES_BACKUP}"
		die "the reference block is still in ${NOTES_FILE}; release notes were not edited."
	fi
	rm -f "${NOTES_BACKUP}"
fi

RELEASE_NOTES="$(cat "${NOTES_FILE}")"
[[ -n "${RELEASE_NOTES//[[:space:]]/}" ]] || die "${NOTES_FILE} is empty."

# ------------------------------------------------------- goreleaser preflight

say "validating the goreleaser configuration."
goreleaser check
goreleaser healthcheck || say "warning: healthcheck reported missing tools (see above)."

SNAPSHOT_SKIP="announce,publish,validate"
if ! command -v syft >/dev/null 2>&1; then
	say "warning: syft is not installed, so the rehearsal will not build SBOMs."
	SNAPSHOT_SKIP="${SNAPSHOT_SKIP},sbom"
fi

# ------------------------------------------------------------- version bump

say "bumping Cargo.toml and Cargo.lock."
if [[ "${DRY_RUN}" -eq 0 ]]; then
	${SED} -i -e "s/^version = \"[0-9.]*\"/version = \"${VERSION}\"/" Cargo.toml
	cargo generate-lockfile
	grep -q "^version = \"${VERSION}\"$" Cargo.toml || die "Cargo.toml version bump did not take."
fi

# ---------------------------------------------------- commit, tag and push

TAG_PUSHED=0
COMMIT_MADE=0
COMMIT_PUSHED=0
RELEASE_PUBLISHED=0

cleanup_failed_release() {
	local status=$?
	[[ ${status} -eq 0 ]] && return 0
	if [[ "${DRY_RUN}" -eq 1 ]]; then
		say "(dry run) rehearsal failed; nothing to roll back."
		return ${status}
	fi
	# Once the release is public the tag is load-bearing: deleting it would
	# orphan the release and every artifact URL in it. Anything that fails
	# after that point is reported and left for the operator to finish.
	if [[ "${RELEASE_PUBLISHED}" -eq 1 ]]; then
		say "the ${TAG} release is already published; leaving the tag and the release in place."
		say "a later step failed (see above) and needs finishing by hand."
		return ${status}
	fi
	if [[ "${TAG_PUSHED}" -eq 1 ]]; then
		say "release failed after the tag was pushed; removing ${TAG} from origin."
		git push --delete origin "${TAG}" || say "warning: could not delete origin ${TAG}; remove it by hand."
	fi
	if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
		say "removing local tag ${TAG}."
		git tag -d "${TAG}" >/dev/null || true
	fi
	if [[ "${COMMIT_PUSHED}" -eq 1 ]]; then
		say "the release commit is already on origin/${BRANCH}; undo it with 'git revert HEAD' or fix forward, not with a reset."
	elif [[ "${COMMIT_MADE}" -eq 1 ]]; then
		say "the release commit is on local ${BRANCH} only; 'git reset --hard HEAD~1' undoes it."
	fi
	return ${status}
}
trap cleanup_failed_release EXIT

run git add Cargo.toml Cargo.lock "${NOTES_FILE}"
run git commit -m "[ci] Verifpal ${VERSION}"
COMMIT_MADE=1
run git push origin "${BRANCH}"
COMMIT_PUSHED=1

run git tag -a "${TAG}" -m "Verifpal ${VERSION}" -m "${RELEASE_NOTES}"
run git push origin "${TAG}"
TAG_PUSHED=1
if [[ "${DRY_RUN}" -eq 1 ]]; then
	say "(dry run) would have tagged and pushed ${TAG}."
else
	say "${TAG} tagged and pushed."
fi

# ------------------------------------------------------------------ publish

verify_generated_manifests() {
	say "verifying that the generated package manifests describe ${VERSION}."
	run git pull --rebase --autostash --quiet
	[[ "${DRY_RUN}" -eq 1 ]] && return 0
	local failed=0
	if ! grep -q "version \"${VERSION}\"" Casks/verifpal.rb 2>/dev/null; then
		say "error: Casks/verifpal.rb does not name ${VERSION}."
		failed=1
	fi
	if ! grep -q "\"version\": \"${VERSION}\"" verifpal.json 2>/dev/null; then
		say "error: verifpal.json does not name ${VERSION}."
		failed=1
	fi
	[[ ${failed} -eq 0 ]] || die "package manifests were not regenerated for ${VERSION}."
	say "package manifests are current."
}

publish_crate() {
	local published
	published="$(curl -sS -H 'User-Agent: verifpal-release' \
		"https://crates.io/api/v1/crates/verifpal/${VERSION}" 2>/dev/null || true)"
	if [[ "${published}" == *"\"num\":\"${VERSION}\""* ]]; then
		say "crates.io already has ${VERSION}; skipping."
		return 0
	fi
	say "publishing ${VERSION} to crates.io."
	run cargo publish --locked
}

if [[ "${LOCAL_PUBLISH}" -eq 1 ]]; then
	say "running goreleaser locally."
	run goreleaser release --clean
	RELEASE_PUBLISHED=1
	verify_generated_manifests
	publish_crate
else
	say "the release itself now runs in CI; watch it with:"
	say "  gh run watch \$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
	say "when it finishes, 'git pull --rebase' brings the regenerated manifests down."
fi

trap - EXIT
if [[ "${DRY_RUN}" -eq 1 ]]; then
	say "(dry run) rehearsal complete; nothing was committed, tagged or published."
else
	say "Verifpal ${VERSION} released."
fi
