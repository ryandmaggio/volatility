#!/usr/bin/env bash
VOL_VERS="3.0.0"
TEST_DIR="test-${VOL_VERS}-output"
DUMP_DIR="test-${VOL_VERS}-dumpdr"
mkdir -p "${TEST_DIR}" "${DUMP_DIR}"

. vars.sh

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"

run-test() {
    start=$(date +%s)
    volatility3 -f "${IMAGE}" --profile="${PROFILE}" ${@} &> "${TEST_DIR}/${1}.txt"
    elapsed=$(($(date +%s) - start))
    if [[ ${?} -eq 0 ]]; then
        printf "[%-28s](took %-4s secs): \e[0;32mSUCCESS\x1b[0;0m\n" "${1}" "${elapsed}"
    else
        printf "[%-28s](took %-4s secs): \e[0;31mFAILURE\x1b[0;0m\n" "${1}" "${elapsed}"
    fi
}

run-test amcache
run-test apihooks
run-test atoms
run-test atomscan
run-test auditpol
run-test bigpools
run-test bioskbd
run-test cachedump
run-test callbacks
run-test clipboard
run-test cmdline
run-test cmdscan
run-test imageinfo
run-test connections
run-test connscan
run-test consoles
run-test crashinfo
run-test deskscan
run-test devicetree
run-test dlldump -p "${DLLDUMP_PID}" -r "${DLLDUMP_RGX}" -D "${DUMP_DIR}"
run-test dlllist
run-test driverirp
run-test drivermodule
run-test driverscan
run-test dumpcerts
run-test dumpfiles -Q "${DUMPFIL_OFT}" -D "${DUMP_DIR}"
run-test dumpregistry -o "${DUMPREG_OFT}" -D "${DUMP_DIR}"
run-test editbox
run-test envars
run-test eventhooks
run-test evtlogs
run-test filescan
run-test gahti
run-test gditimers
run-test gdt
run-test getservicesids
run-test getsids
run-test handles
run-test hashdump
run-test hibinfo
run-test hivedump
run-test hivelist
run-test hivescan
run-test hpakextract
run-test hpakinfo
run-test idt
run-test iehistory
run-test imagecopy
run-test impscan
run-test joblinks
#run-test kdbgscan
#run-test kpcrscan
run-test ldrmodules
run-test limeinfo
run-test lsadump
run-test machoinfo
run-test malfind
run-test mbrparser
run-test memdump -p "${MEMDUMP_PID}" -D "${DUMP_DIR}"
run-test memmap
run-test messagehooks
run-test mftparser
run-test moddump -r "${MODDUMP_RGX}" -D "${DUMP_DIR}"
run-test modscan
run-test modules
run-test multiscan
run-test mutantscan
run-test netscan
run-test notepad
run-test objtypescan
run-test patcher
run-test poolpeek --tag "${POOLPEEK_TAG}"
run-test pooltracker
run-test printkey
run-test privs
run-test procdump -p "${PROCDUMP_PID}" -D "${DUMP_DIR}"
run-test pslist
run-test psscan
run-test pstree
run-test psxview
run-test qemuinfo
run-test raw2dmp
run-test screenshot
run-test servicediff
run-test sessions
run-test shellbags
run-test shimcache
run-test shutdowntime
run-test sockets
run-test sockscan
run-test ssdt
run-test strings
run-test svcscan
run-test symlinkscan
run-test thrdscan
run-test threads
run-test timeliner
run-test timers
run-test truecryptmaster
run-test truecryptpassphrase
run-test truecryptsummary
run-test unloadedmodules
run-test userassist
run-test userhandles
#run-test vaddump
#run-test vadinfo
#run-test vadtree
#run-test vadwalk
run-test vboxinfo
run-test verinfo
run-test vmwareinfo
#run-test volshell
run-test win10cookie
run-test windows
run-test wintree
run-test wndscan
run-test yarascan
