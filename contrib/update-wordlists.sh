#!/bin/bash
# Fetch the newest profanity lists from ovos-good-manners-pipeline-plugin (dev)
# and note the commit in wordlists/SOURCE.md. Needs gh.
set -euo pipefail
cd "$(dirname "$0")/../src/unseenet_watchman/wordlists"
R=OpenVoiceOS/ovos-good-manners-pipeline-plugin
SHA=$(gh api "repos/$R/commits/dev" -q .sha)
for l in da-dk de-de en-us; do
  gh api "repos/$R/contents/ovos_good_manners_pipeline_plugin/locale/$l/foul_language.voc?ref=$SHA" \
    -q .content | base64 -d > "profanity-${l%%-*}.txt"
done
sed -i -E "s/commit \`[0-9a-f]{40}\` \([^)]*\)/commit \`$SHA\` ($(date +'%-d %b %Y'))/" SOURCE.md
git --no-pager diff --stat -- .
