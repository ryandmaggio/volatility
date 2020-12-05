#!/usr/bin/env bash
VERS_1="2.6.1"
VERS_2="3.0.0"
TEST_DIR_1="test-${VERS_1}-output"
TEST_DIR_2="test-${VERS_2}-output"
DUMP_DIR_1="test-${VERS_1}-dumpdr"
DUMP_DIR_2="test-${VERS_2}-dumpdr"
#
# DIFF CONSOLE OUTPUT FILES
#
total_count=0
success_count=0
echo "[DIFFING CONSOLE OUTPUT FILES]"
for file in $(ls "${TEST_DIR_1}"); do
    total_count=$((${total_count} + 1))
    if [[ -f "${TEST_DIR_2}/${file}" ]]; then
        &>/dev/null diff <(tail -n+2 "${TEST_DIR_1}/${file}") <(tail -n+2 "${TEST_DIR_2}/${file}")
        if [[ ${?} -eq 0 ]]; then
            success_count=$((${success_count} + 1))
            printf "[%-28s]: \e[0;32mPASSED (same output)\x1b[0;0m\n" "${file}"
        else
            printf "[%-28s]: \e[0;31mFAILED (output differs)\x1b[0;0m\n" "${file}"
        fi
    else
        printf "[%-28s]: \e[0;31mFAILED (file not found)\x1b[0;0m\n" "${file}"
    fi
done
echo "[${success_count}/${total_count} tests passed]"
#
# DIFF DUMP OUTPUT FILES
#
total_count=0
success_count=0
echo "[DIFFING DUMP OUTPUT FILES]"
for file in $(ls "${DUMP_DIR_1}"); do
    total_count=$((${total_count} + 1))
    if [[ -f "${DUMP_DIR_2}/${file}" ]]; then
        first=$(cat "${DUMP_DIR_1}/${file}" | sha256sum -b - | cut -d' ' -f1)
        second=$(cat "${DUMP_DIR_2}/${file}" | sha256sum -b - | cut -d' ' -f1)
        if [[ "${first}" == "${second}" ]]; then
            success_count=$((${success_count} + 1))
            printf "[%-28s]: \e[0;32mPASSED (same output)\x1b[0;0m\n" "${file}"
        else
            printf "[%-28s]: \e[0;31mFAILED (output differs)\x1b[0;0m\n" "${file}"
        fi
    else
        printf "[%-28s]: \e[0;31mFAILED (file not found)\x1b[0;0m\n" "${file}"
    fi
done
echo "[${success_count}/${total_count} tests passed]"
