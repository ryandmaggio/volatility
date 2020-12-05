#!/usr/bin/env bash
. vars.sh

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"
volatility2 -f "${IMAGE}" --profile="${PROFILE}" ${@}
