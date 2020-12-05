#!/usr/bin/env bash
. vars.sh

PLUGIN_OPTION=""
if [ ! -z "${PLUGINS}" ]; then
    PLUGIN_OPTION="--plugins=${PLUGINS}"
fi

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"
start=$(date +%s)
volatility3 -f "${IMAGE}" --profile="${PROFILE}" "${PLUGIN_OPTION}" ${@} |& tee output.txt
elapsed=$(($(date +%s) - start))
printf "[took %-4s secs]\n" "${elapsed}"
