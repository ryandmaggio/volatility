#!/usr/bin/env bash
. vars.sh

PLUGIN_OPTION=""
if [ ! -z "${PLUGINS}" ]; then
    PLUGIN_OPTION="--plugins=${PLUGINS}"
fi

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"
start=$(date +%s)
volatility2 -f "${IMAGE}" --profile="${PROFILE}" "${PLUGIN_OPTION}" ${@} |& tee output.txt
status=${?}
elapsed=$(($(date +%s) - start))
if [[ ${status} -eq 0 ]]; then
    printf "(took %-4s secs): \e[0;32mSUCCESS\x1b[0;0m\n" "${elapsed}"
else
    printf "(took %-4s secs): \e[0;31mFAILURE\x1b[0;0m\n" "${elapsed}"
fi
