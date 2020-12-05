#!/usr/bin/env bash
. vars.sh

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"
volatility3 -f "${IMAGE}" --profile="${PROFILE}" ${@}

