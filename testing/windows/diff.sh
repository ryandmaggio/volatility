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
for file in $(ls "${TEST_DIR_1}"); do
    if [[ -f "${TEST_DIR_2}/${file}" ]]; then
        &>/dev/null diff <(tail -n+2 "${TEST_DIR_1}/${file}") <(tail -n+2 "${TEST_DIR_2}/${file}")
        if [[ ${?} -eq 0 ]]; then
            printf "[%-28s]: \e[0;32mSUCCESS (same output)\x1b[0;0m\n" "${file}"
        else
            printf "[%-28s]: \e[0;31mFAILURE (output differs)\x1b[0;0m\n" "${file}"
        fi
    else
        printf "[%-28s]: \e[0;31mFAILURE (file not found)\x1b[0;0m\n" "${file}"
    fi
done
#
# DIFF DUMP OUTPUT FILES
#
for file in $(ls "${DUMP_DIR_1}"); do
    if [[ -f "${DUMP_DIR_2}/${file}" ]]; then
        first=$(cat "${DUMP_DIR_1}/${file}" | sha256sum -b - | cut -d' ' -f1)
        second=$(cat "${DUMP_DIR_2}/${file}" | sha256sum -b - | cut -d' ' -f1)
        if [[ "${first}" != "${second}" ]]; then
            printf "[%-28s]: \e[0;32mSUCCESS (same output)\x1b[0;0m\n" "${file}"
        else
            printf "[%-28s]: \e[0;31mFAILURE (output differs)\x1b[0;0m\n" "${file}"
        fi
    else
        printf "[%-28s]: \e[0;31mFAILURE (file not found)\x1b[0;0m\n" "${file}"
    fi
done
