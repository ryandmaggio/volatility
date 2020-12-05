#!/usr/bin/env bash
VOL_VERS="2.6.1"
TEST_DIR="test-${VOL_VERS}-output"
DUMP_DIR="test-${VOL_VERS}-dumpdr"
mkdir -p "${TEST_DIR}" "${DUMP_DIR}"

. vars.sh

PLUGIN_OPTION=""
if [ ! -z "${PLUGINS}" ]; then
    PLUGIN_OPTION="--plugins=${PLUGINS}"
fi

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"

run-test() {
    start=$(date +%s)
    volatility2 "${PLUGIN_OPTION}" -f "${IMAGE}" --profile="${PROFILE}" ${@} &> "${TEST_DIR}/${1}.txt"
    status=${?}
    elapsed=$(($(date +%s) - start))
    if [[ ${status} -eq 0 ]]; then
        printf "[%-28s](took %-4s secs): \e[0;32mPASSED\x1b[0;0m\n" "${1}" "${elapsed}"
    else
        printf "[%-28s](took %-4s secs): \e[0;31mFAILED\x1b[0;0m\n" "${1}" "${elapsed}"
    fi
}

run-test limeinfo
#run-test linux_apihooks
run-test linux_arp
run-test linux_aslr_shift
run-test linux_banner
run-test linux_bash
run-test linux_bash_env
run-test linux_bash_hash
run-test linux_check_afinfo
run-test linux_check_creds
run-test linux_check_evt_arm
run-test linux_check_fop
run-test linux_check_idt
run-test linux_check_inline_kernel
run-test linux_check_modules
run-test linux_check_syscall
run-test linux_check_syscall_arm
run-test linux_check_tty
run-test linux_cpuinfo
run-test linux_dentry_cache
run-test linux_dmesg
run-test linux_dump_map
run-test linux_dynamic_env
run-test linux_elfs
run-test linux_enumerate_files
run-test linux_find_file
run-test linux_getcwd
run-test linux_hidden_modules
run-test linux_ifconfig
run-test linux_info_regs
run-test linux_iomem
run-test linux_kernel_opened_files
run-test linux_keyboard_notifiers
run-test linux_ldrmodules
run-test linux_library_list
run-test linux_librarydump
run-test linux_list_raw
run-test linux_lsmod
run-test linux_lsof
run-test linux_malfind
run-test linux_memmap
run-test linux_moddump
run-test linux_mount
run-test linux_mount_cache
run-test linux_netfilter
run-test linux_netscan
run-test linux_netstat
run-test linux_pidhashtable
run-test linux_pkt_queues
run-test linux_plthook
run-test linux_proc_maps
run-test linux_proc_maps_rb
run-test linux_procdump
run-test linux_process_hollow
run-test linux_psaux
run-test linux_psenv
run-test linux_pslist
run-test linux_pslist_cache
run-test linux_psscan
run-test linux_pstree
run-test linux_psxview
run-test linux_recover_filesystem
run-test linux_route_cache
run-test linux_sk_buff_cache
run-test linux_slabinfo
run-test linux_strings
run-test linux_threads
run-test linux_tmpfs
run-test linux_truecrypt_passphrase
run-test linux_vma_cache
#run-test linux_volshell
run-test linux_yarascan
