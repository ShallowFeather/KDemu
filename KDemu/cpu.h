#pragma once

/* segment descriptor fields */
#define DESC_G_SHIFT    23
#define DESC_G_MASK     (1 << DESC_G_SHIFT)
#define DESC_B_SHIFT    22
#define DESC_B_MASK     (1 << DESC_B_SHIFT)
#define DESC_L_SHIFT    21 /* x86_64 only : 64 bit code segment */
#define DESC_L_MASK     (1 << DESC_L_SHIFT)
#define DESC_AVL_SHIFT  20
#define DESC_AVL_MASK   (1 << DESC_AVL_SHIFT)
#define DESC_P_SHIFT    15
#define DESC_P_MASK     (1 << DESC_P_SHIFT)
#define DESC_DPL_SHIFT  13
#define DESC_DPL_MASK   (3 << DESC_DPL_SHIFT)
#define DESC_S_SHIFT    12
#define DESC_S_MASK     (1 << DESC_S_SHIFT)
#define DESC_TYPE_SHIFT 8
#define DESC_TYPE_MASK  (15 << DESC_TYPE_SHIFT)
#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11) /* 1=code segment 0=data segment */
#define DESC_C_MASK     (1 << 10) /* code: conforming */
#define DESC_R_MASK     (1 << 9)  /* code: readable */

#define DESC_E_MASK     (1 << 10) /* data: expansion direction */
#define DESC_W_MASK     (1 << 9)  /* data: writable */

#define DESC_TSS_BUSY_MASK (1 << 9)

/* eflags masks */
#define CC_C    0x0001
#define CC_P    0x0004
#define CC_A    0x0010
#define CC_Z    0x0040
#define CC_S    0x0080
#define CC_O    0x0800

#define TF_SHIFT   8
#define IOPL_SHIFT 12
#define VM_SHIFT   17

#define TF_MASK                 0x00000100
#define IF_MASK                 0x00000200
#define DF_MASK                 0x00000400
#define IOPL_MASK               0x00003000
#define NT_MASK                 0x00004000
#define RF_MASK                 0x00010000
#define VM_MASK                 0x00020000
#define AC_MASK                 0x00040000
#define VIF_MASK                0x00080000
#define VIP_MASK                0x00100000
#define ID_MASK                 0x00200000

/* hidden flags - used internally by qemu to represent additional cpu
   states. Only the INHIBIT_IRQ, SMM and SVMI are not redundant. We
   avoid using the IOPL_MASK, TF_MASK, VM_MASK and AC_MASK bit
   positions to ease oring with eflags. */
   /* current cpl */
#define HF_CPL_SHIFT         0
/* true if hardware interrupts must be disabled for next instruction */
#define HF_INHIBIT_IRQ_SHIFT 3
/* 16 or 32 segments */
#define HF_CS32_SHIFT        4
#define HF_SS32_SHIFT        5
/* zero base for DS, ES and SS : can be '0' only in 32 bit CS segment */
#define HF_ADDSEG_SHIFT      6
/* copy of CR0.PE (protected mode) */
#define HF_PE_SHIFT          7
#define HF_TF_SHIFT          8 /* must be same as eflags */
#define HF_MP_SHIFT          9 /* the order must be MP, EM, TS */
#define HF_EM_SHIFT         10
#define HF_TS_SHIFT         11
#define HF_IOPL_SHIFT       12 /* must be same as eflags */
#define HF_LMA_SHIFT        14 /* only used on x86_64: long mode active */
#define HF_CS64_SHIFT       15 /* only used on x86_64: 64 bit code segment  */
#define HF_RF_SHIFT         16 /* must be same as eflags */
#define HF_VM_SHIFT         17 /* must be same as eflags */
#define HF_AC_SHIFT         18 /* must be same as eflags */
#define HF_SMM_SHIFT        19 /* CPU in SMM mode */
#define HF_SVME_SHIFT       20 /* SVME enabled (copy of EFER.SVME) */
#define HF_GUEST_SHIFT      21 /* SVM intercepts are active */
#define HF_OSFXSR_SHIFT     22 /* CR4.OSFXSR */
#define HF_SMAP_SHIFT       23 /* CR4.SMAP */
#define HF_IOBPT_SHIFT      24 /* an io breakpoint enabled */
#define HF_MPX_EN_SHIFT     25 /* MPX Enabled (CR4+XCR0+BNDCFGx) */
#define HF_MPX_IU_SHIFT     26 /* BND registers in-use */

#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)
#define HF_INHIBIT_IRQ_MASK  (1 << HF_INHIBIT_IRQ_SHIFT)
#define HF_CS32_MASK         (1 << HF_CS32_SHIFT)
#define HF_SS32_MASK         (1 << HF_SS32_SHIFT)
#define HF_ADDSEG_MASK       (1 << HF_ADDSEG_SHIFT)
#define HF_PE_MASK           (1 << HF_PE_SHIFT)
#define HF_TF_MASK           (1 << HF_TF_SHIFT)
#define HF_MP_MASK           (1 << HF_MP_SHIFT)
#define HF_EM_MASK           (1 << HF_EM_SHIFT)
#define HF_TS_MASK           (1 << HF_TS_SHIFT)
#define HF_IOPL_MASK         (3 << HF_IOPL_SHIFT)
#define HF_LMA_MASK          (1 << HF_LMA_SHIFT)
#define HF_CS64_MASK         (1 << HF_CS64_SHIFT)
#define HF_RF_MASK           (1 << HF_RF_SHIFT)
#define HF_VM_MASK           (1 << HF_VM_SHIFT)
#define HF_AC_MASK           (1 << HF_AC_SHIFT)
#define HF_SMM_MASK          (1 << HF_SMM_SHIFT)
#define HF_SVME_MASK         (1 << HF_SVME_SHIFT)
#define HF_GUEST_MASK        (1 << HF_GUEST_SHIFT)
#define HF_OSFXSR_MASK       (1 << HF_OSFXSR_SHIFT)
#define HF_SMAP_MASK         (1 << HF_SMAP_SHIFT)
#define HF_IOBPT_MASK        (1 << HF_IOBPT_SHIFT)
#define HF_MPX_EN_MASK       (1 << HF_MPX_EN_SHIFT)
#define HF_MPX_IU_MASK       (1 << HF_MPX_IU_SHIFT)

/* hflags2 */

#define HF2_GIF_SHIFT            0 /* if set CPU takes interrupts */
#define HF2_HIF_SHIFT            1 /* value of IF_MASK when entering SVM */
#define HF2_NMI_SHIFT            2 /* CPU serving NMI */
#define HF2_VINTR_SHIFT          3 /* value of V_INTR_MASKING bit */
#define HF2_SMM_INSIDE_NMI_SHIFT 4 /* CPU serving SMI nested inside NMI */
#define HF2_MPX_PR_SHIFT         5 /* BNDCFGx.BNDPRESERVE */
#define HF2_NPT_SHIFT            6 /* Nested Paging enabled */
#define HF2_IGNNE_SHIFT          7 /* Ignore CR0.NE=0 */

#define HF2_GIF_MASK            (1 << HF2_GIF_SHIFT)
#define HF2_HIF_MASK            (1 << HF2_HIF_SHIFT)
#define HF2_NMI_MASK            (1 << HF2_NMI_SHIFT)
#define HF2_VINTR_MASK          (1 << HF2_VINTR_SHIFT)
#define HF2_SMM_INSIDE_NMI_MASK (1 << HF2_SMM_INSIDE_NMI_SHIFT)
#define HF2_MPX_PR_MASK         (1 << HF2_MPX_PR_SHIFT)
#define HF2_NPT_MASK            (1 << HF2_NPT_SHIFT)
#define HF2_IGNNE_MASK          (1 << HF2_IGNNE_SHIFT)

#define CR0_PE_SHIFT 0
#define CR0_MP_SHIFT 1

#define CR0_PE_MASK  (1U << 0)
#define CR0_MP_MASK  (1U << 1)
#define CR0_EM_MASK  (1U << 2)
#define CR0_TS_MASK  (1U << 3)
#define CR0_ET_MASK  (1U << 4)
#define CR0_NE_MASK  (1U << 5)
#define CR0_WP_MASK  (1U << 16)
#define CR0_AM_MASK  (1U << 18)
#define CR0_PG_MASK  (1U << 31)

#define CR4_VME_MASK  (1U << 0)
#define CR4_PVI_MASK  (1U << 1)
#define CR4_TSD_MASK  (1U << 2)
#define CR4_DE_MASK   (1U << 3)
#define CR4_PSE_MASK  (1U << 4)
#define CR4_PAE_MASK  (1U << 5)
#define CR4_MCE_MASK  (1U << 6)
#define CR4_PGE_MASK  (1U << 7)
#define CR4_PCE_MASK  (1U << 8)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK  (1U << 10)
#define CR4_LA57_MASK   (1U << 12)
#define CR4_VMXE_MASK   (1U << 13)
#define CR4_SMXE_MASK   (1U << 14)
#define CR4_FSGSBASE_MASK (1U << 16)
#define CR4_PCIDE_MASK  (1U << 17)
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_SMEP_MASK   (1U << 20)
#define CR4_SMAP_MASK   (1U << 21)
#define CR4_PKE_MASK   (1U << 22)

#define DR6_BD          (1 << 13)
#define DR6_BS          (1 << 14)
#define DR6_BT          (1 << 15)
#define DR6_FIXED_1     0xffff0ff0

#define DR7_GD          (1 << 13)
#define DR7_TYPE_SHIFT  16
#define DR7_LEN_SHIFT   18
#define DR7_FIXED_1     0x00000400
#define DR7_GLOBAL_BP_MASK   0xaa
#define DR7_LOCAL_BP_MASK    0x55
#define DR7_MAX_BP           4
#define DR7_TYPE_BP_INST     0x0
#define DR7_TYPE_DATA_WR     0x1
#define DR7_TYPE_IO_RW       0x2
#define DR7_TYPE_DATA_RW     0x3

#define PG_PRESENT_BIT  0
#define PG_RW_BIT       1
#define PG_USER_BIT     2
#define PG_PWT_BIT      3
#define PG_PCD_BIT      4
#define PG_ACCESSED_BIT 5
#define PG_DIRTY_BIT    6
#define PG_PSE_BIT      7
#define PG_GLOBAL_BIT   8
#define PG_PSE_PAT_BIT  12
#define PG_PKRU_BIT     59
#define PG_NX_BIT       63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK       (1 << PG_RW_BIT)
#define PG_USER_MASK     (1 << PG_USER_BIT)
#define PG_PWT_MASK      (1 << PG_PWT_BIT)
#define PG_PCD_MASK      (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK    (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK      (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK   (1 << PG_GLOBAL_BIT)
#define PG_PSE_PAT_MASK  (1 << PG_PSE_PAT_BIT)
#define PG_ADDRESS_MASK  0x000ffffffffff000LL
#define PG_HI_RSVD_MASK  (PG_ADDRESS_MASK & ~PHYS_ADDR_MASK)
#define PG_HI_USER_MASK  0x7ff0000000000000LL
#define PG_PKRU_MASK     (15ULL << PG_PKRU_BIT)
#define PG_NX_MASK       (1ULL << PG_NX_BIT)

#define PG_ERROR_W_BIT     1

#define PG_ERROR_P_MASK    0x01
#define PG_ERROR_W_MASK    (1 << PG_ERROR_W_BIT)
#define PG_ERROR_U_MASK    0x04
#define PG_ERROR_RSVD_MASK 0x08
#define PG_ERROR_I_D_MASK  0x10
#define PG_ERROR_PK_MASK   0x20

#define MCG_CTL_P       (1ULL<<8)   /* MCG_CAP register available */
#define MCG_SER_P       (1ULL<<24) /* MCA recovery/new status bits */
#define MCG_LMCE_P      (1ULL<<27) /* Local Machine Check Supported */

#define MCE_CAP_DEF     (MCG_CTL_P|MCG_SER_P)
#define MCE_BANKS_DEF   10

#define MCG_CAP_BANKS_MASK 0xff

#define MCG_STATUS_RIPV (1ULL<<0)   /* restart ip valid */
#define MCG_STATUS_EIPV (1ULL<<1)   /* ip points to correct instruction */
#define MCG_STATUS_MCIP (1ULL<<2)   /* machine check in progress */
#define MCG_STATUS_LMCE (1ULL<<3)   /* Local MCE signaled */

#define MCG_EXT_CTL_LMCE_EN (1ULL<<0) /* Local MCE enabled */

#define MCI_STATUS_VAL   (1ULL<<63)  /* valid error */
#define MCI_STATUS_OVER  (1ULL<<62)  /* previous errors lost */
#define MCI_STATUS_UC    (1ULL<<61)  /* uncorrected error */
#define MCI_STATUS_EN    (1ULL<<60)  /* error enabled */
#define MCI_STATUS_MISCV (1ULL<<59)  /* misc error reg. valid */
#define MCI_STATUS_ADDRV (1ULL<<58)  /* addr reg. valid */
#define MCI_STATUS_PCC   (1ULL<<57)  /* processor context corrupt */
#define MCI_STATUS_S     (1ULL<<56)  /* Signaled machine check */
#define MCI_STATUS_AR    (1ULL<<55)  /* Action required */

/* MISC register defines */
#define MCM_ADDR_SEGOFF  0      /* segment offset */
#define MCM_ADDR_LINEAR  1      /* linear address */
#define MCM_ADDR_PHYS    2      /* physical address */
#define MCM_ADDR_MEM     3      /* memory address */
#define MCM_ADDR_GENERIC 7      /* generic */

#define MSR_IA32_TSC                    0x10
#define MSR_IA32_APICBASE               0x1b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_EXTD          (1 << 10)
#define MSR_IA32_APICBASE_BASE          (0xfffffU<<12)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_TSC_ADJUST                  0x0000003b
#define MSR_IA32_SPEC_CTRL              0x48
#define MSR_VIRT_SSBD                   0xc001011f
#define MSR_IA32_PRED_CMD               0x49
#define MSR_IA32_UCODE_REV              0x8b
#define MSR_IA32_CORE_CAPABILITY        0xcf

#define MSR_IA32_ARCH_CAPABILITIES      0x10a
#define ARCH_CAP_TSX_CTRL_MSR		(1<<7)

#define MSR_IA32_TSX_CTRL		0x122
#define MSR_IA32_TSCDEADLINE            0x6e0

#define FEATURE_CONTROL_LOCKED                    (1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX (1<<2)
#define FEATURE_CONTROL_LMCE                      (1<<20)

#define MSR_P6_PERFCTR0                 0xc1

#define MSR_IA32_SMBASE                 0x9e
#define MSR_SMI_COUNT                   0x34
#define MSR_MTRRcap                     0xfe
#define MSR_MTRRcap_VCNT                8
#define MSR_MTRRcap_FIXRANGE_SUPPORT    (1 << 8)
#define MSR_MTRRcap_WC_SUPPORTED        (1 << 10)

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176

#define MSR_MCG_CAP                     0x179
#define MSR_MCG_STATUS                  0x17a
#define MSR_MCG_CTL                     0x17b
#define MSR_MCG_EXT_CTL                 0x4d0

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MSR_IA32_MISC_ENABLE            0x1a0
/* Indicates good rep/movs microcode on some processors: */
#define MSR_IA32_MISC_ENABLE_DEFAULT    1
#define MSR_IA32_MISC_ENABLE_MWAIT      (1ULL << 18)

#define MSR_MTRRphysBase(reg)           (0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg)           (0x200 + 2 * (reg) + 1)

#define MSR_MTRRphysIndex(addr)         ((((addr) & ~1u) - 0x200) / 2)

#define MSR_MTRRfix64K_00000            0x250
#define MSR_MTRRfix16K_80000            0x258
#define MSR_MTRRfix16K_A0000            0x259
#define MSR_MTRRfix4K_C0000             0x268
#define MSR_MTRRfix4K_C8000             0x269
#define MSR_MTRRfix4K_D0000             0x26a
#define MSR_MTRRfix4K_D8000             0x26b
#define MSR_MTRRfix4K_E0000             0x26c
#define MSR_MTRRfix4K_E8000             0x26d
#define MSR_MTRRfix4K_F0000             0x26e
#define MSR_MTRRfix4K_F8000             0x26f

#define MSR_PAT                         0x277

#define MSR_MTRRdefType                 0x2ff

#define MSR_CORE_PERF_FIXED_CTR0        0x309
#define MSR_CORE_PERF_FIXED_CTR1        0x30a
#define MSR_CORE_PERF_FIXED_CTR2        0x30b
#define MSR_CORE_PERF_FIXED_CTR_CTRL    0x38d
#define MSR_CORE_PERF_GLOBAL_STATUS     0x38e
#define MSR_CORE_PERF_GLOBAL_CTRL       0x38f
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL   0x390

#define MSR_MC0_CTL                     0x400
#define MSR_MC0_STATUS                  0x401
#define MSR_MC0_ADDR                    0x402
#define MSR_MC0_MISC                    0x403

#define MSR_IA32_RTIT_OUTPUT_BASE       0x560
#define MSR_IA32_RTIT_OUTPUT_MASK       0x561
#define MSR_IA32_RTIT_CTL               0x570
#define MSR_IA32_RTIT_STATUS            0x571
#define MSR_IA32_RTIT_CR3_MATCH         0x572
#define MSR_IA32_RTIT_ADDR0_A           0x580
#define MSR_IA32_RTIT_ADDR0_B           0x581
#define MSR_IA32_RTIT_ADDR1_A           0x582
#define MSR_IA32_RTIT_ADDR1_B           0x583
#define MSR_IA32_RTIT_ADDR2_A           0x584
#define MSR_IA32_RTIT_ADDR2_B           0x585
#define MSR_IA32_RTIT_ADDR3_A           0x586
#define MSR_IA32_RTIT_ADDR3_B           0x587
#define MAX_RTIT_ADDRS                  8

#define MSR_EFER                        0xc0000080

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_SVME  (1 << 12)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084
#define MSR_FSBASE                      0xc0000100
#define MSR_GSBASE                      0xc0000101
#define MSR_KERNELGSBASE                0xc0000102
#define MSR_TSC_AUX                     0xc0000103

#define MSR_VM_HSAVE_PA                 0xc0010117

#define MSR_IA32_BNDCFGS                0x00000d90
#define MSR_IA32_XSS                    0x00000da0
#define MSR_IA32_UMWAIT_CONTROL         0xe1

#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490
#define MSR_IA32_VMX_VMFUNC             0x00000491

#define XSTATE_FP_BIT                   0
#define XSTATE_SSE_BIT                  1
#define XSTATE_YMM_BIT                  2
#define XSTATE_BNDREGS_BIT              3
#define XSTATE_BNDCSR_BIT               4
#define XSTATE_OPMASK_BIT               5
#define XSTATE_ZMM_Hi256_BIT            6
#define XSTATE_Hi16_ZMM_BIT             7
#define XSTATE_PKRU_BIT                 9

#define XSTATE_FP_MASK                  (1ULL << XSTATE_FP_BIT)
#define XSTATE_SSE_MASK                 (1ULL << XSTATE_SSE_BIT)
#define XSTATE_YMM_MASK                 (1ULL << XSTATE_YMM_BIT)
#define XSTATE_BNDREGS_MASK             (1ULL << XSTATE_BNDREGS_BIT)
#define XSTATE_BNDCSR_MASK              (1ULL << XSTATE_BNDCSR_BIT)
#define XSTATE_OPMASK_MASK              (1ULL << XSTATE_OPMASK_BIT)
#define XSTATE_ZMM_Hi256_MASK           (1ULL << XSTATE_ZMM_Hi256_BIT)
#define XSTATE_Hi16_ZMM_MASK            (1ULL << XSTATE_Hi16_ZMM_BIT)
#define XSTATE_PKRU_MASK                (1ULL << XSTATE_PKRU_BIT)