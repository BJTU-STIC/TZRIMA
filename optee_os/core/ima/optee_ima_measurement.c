/*
 * OP-TEE IMA Measurement Agent
 * Hash calculation and measurement functions
 * 
 * Copyright (c) 2024, OP-TEE IMA
 */

#include <kernel/optee_ima.h>
#include <crypto/crypto.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>
#include <stdio.h>

/* ===================================================================
 * Initialization
 * =================================================================== */

TEE_Result ima_measurement_init(struct ima_measurement_agent *agent)
{
    if (!agent) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_init(&agent->lock);
    agent->measurement_count = 0;
    agent->initialized = true;
    /* init periodic measurement */
    agent->periodic_interval_ms = 0;
    agent->last_check_time_ms = 0;
    agent->baseline_initialized = false;
    agent->periodic_check_count = 0;
    agent->periodic_enabled = false;
    memset(agent->kernel_text_baseline, 0, IMA_HASH_SIZE);
    memset(agent->kernel_rodata_baseline, 0, IMA_HASH_SIZE);
    
    DMSG("IMA: Measurement agent initialized");
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * Core Measurement Function
 * =================================================================== */

TEE_Result optee_ima_measure(const struct ima_event_context *ctx,
                              uint8_t *hash_out)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_measurement_agent *agent = &ima_ctx->measurement_agent;
    TEE_Result res;
    void *hash_ctx = NULL;
    
    if (!agent->initialized) {
        EMSG("IMA: Measurement agent not initialized");
        return TEE_ERROR_BAD_STATE;
    }
    
    if (!ctx || !hash_out) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    /* Allocate hash context */
    res = crypto_hash_alloc_ctx(&hash_ctx, IMA_HASH_ALG);
    if (res != TEE_SUCCESS) {
        EMSG("IMA: Failed to allocate hash context: 0x%08x", res);
        return res;
    }
    
    /* Initialize hash */
    res = crypto_hash_init(hash_ctx);
    if (res != TEE_SUCCESS) {
        EMSG("IMA: Failed to initialize hash: 0x%08x", res);
        goto out;
    }
    
    /* Hash based on event type */
    if (ctx->binary_data && ctx->binary_data_len > 0) {
        /* Hash binary data (TA image, kernel, etc.) */
        res = crypto_hash_update(hash_ctx, ctx->binary_data, ctx->binary_data_len);
        if (res != TEE_SUCCESS) {
            EMSG("IMA: Failed to hash binary data: 0x%08x", res);
            goto out;
        }
        
        DMSG("IMA: Measured %zu bytes of binary data", ctx->binary_data_len);
    } else {
        /* Hash event context for non-binary measurements */
        /* Start with UUID */
        res = crypto_hash_update(hash_ctx, (uint8_t *)&ctx->uuid, sizeof(TEE_UUID));
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        /* Add event type */
        uint32_t event_type = ctx->event_type;
        res = crypto_hash_update(hash_ctx, (uint8_t *)&event_type, sizeof(event_type));
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        /* Add syscall ID if present */
        if (ctx->event_type == EVENT_TYPE_SYSCALL) {
            res = crypto_hash_update(hash_ctx, (uint8_t *)&ctx->syscall_id,
                                      sizeof(ctx->syscall_id));
            if (res != TEE_SUCCESS) {
                goto out;
            }
        }
        
        /* Add command ID if present (for TA command invocation) */
        if (ctx->event_type == EVENT_TYPE_TA_COMMAND_INVOKE) {
            res = crypto_hash_update(hash_ctx, (uint8_t *)&ctx->syscall_id,
                                      sizeof(ctx->syscall_id));
            if (res != TEE_SUCCESS) {
                goto out;
            }
        }
        
        /* Add event-specific data if present */
        if (ctx->event_data && ctx->event_data_len > 0) {
            res = crypto_hash_update(hash_ctx, ctx->event_data, ctx->event_data_len);
            if (res != TEE_SUCCESS) {
                goto out;
            }
        }
        
        DMSG("IMA: Measured event context (type=%d)", ctx->event_type);
    }
    
    /* Finalize hash */
    res = crypto_hash_final(hash_ctx, hash_out, IMA_HASH_SIZE);
    if (res != TEE_SUCCESS) {
        EMSG("IMA: Failed to finalize hash: 0x%08x", res);
        goto out;
    }
    
    /* Update statistics */
    mutex_lock(&agent->lock);
    agent->measurement_count++;
    mutex_unlock(&agent->lock);
    
#ifdef IMA_DEBUG
    /* Display hash in debug mode */
    char hash_str[16];
    snprintf(hash_str, sizeof(hash_str), "%02x%02x%02x%02x...",
             hash_out[0], hash_out[1], hash_out[2], hash_out[3]);
    DMSG("IMA: Measurement #%llu: %s", agent->measurement_count, hash_str);
#endif

out:
    if (hash_ctx) {
        crypto_hash_free_ctx(hash_ctx);
    }
    return res;
}

/* ===================================================================
 * Extended Measurement Functions
 * =================================================================== */

TEE_Result optee_ima_measure_memory_region(paddr_t paddr, size_t size,
                                            uint8_t *hash_out)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_measurement_agent *agent = &ima_ctx->measurement_agent;
    TEE_Result res;
    void *hash_ctx = NULL;
    vaddr_t vaddr;
    
    if (!agent->initialized) {
        return TEE_ERROR_BAD_STATE;
    }
    
    if (!hash_out || size == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    /* Convert physical to virtual address */
    //vaddr = (vaddr_t)phys_to_virt(paddr, MEM_AREA_TEE_RAM, size);
    vaddr = (vaddr_t)phys_to_virt(paddr, MEM_AREA_TEE_RAM, 256);
    if (!vaddr) {
        EMSG("IMA: Failed to map paddr 0x%lx", (unsigned long)paddr);
        return TEE_ERROR_ACCESS_DENIED;
    }
    
    /* Allocate hash context */
    res = crypto_hash_alloc_ctx(&hash_ctx, IMA_HASH_ALG);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    /* Initialize hash */
    res = crypto_hash_init(hash_ctx);
    if (res != TEE_SUCCESS) {
        goto out;
    }
    
    /* Hash the memory region */
    res = crypto_hash_update(hash_ctx, (const uint8_t *)vaddr, size);
    if (res != TEE_SUCCESS) {
        EMSG("IMA: Failed to hash memory region: 0x%08x", res);
        goto out;
    }
    
    /* Finalize hash */
    res = crypto_hash_final(hash_ctx, hash_out, IMA_HASH_SIZE);
    if (res == TEE_SUCCESS) {
        /* Update statistics */
        mutex_lock(&agent->lock);
        agent->measurement_count++;
        mutex_unlock(&agent->lock);
        
        DMSG("IMA: Measured memory region paddr=0x%lx size=%zu",
             (unsigned long)paddr, size);
    }

out:
    if (hash_ctx) {
        crypto_hash_free_ctx(hash_ctx);
    }
    return res;
}

TEE_Result optee_ima_measure_kernel_structure(const char *structure_name,
                                                const void *data, size_t size)
{
    struct ima_event_context ctx = {
        .event_type = EVENT_TYPE_KERNEL_BOOT,
        .binary_data = data,
        .binary_data_len = size
    };
    uint8_t hash[IMA_HASH_SIZE];
    TEE_Result res;
    
    if (!structure_name || !data || size == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    DMSG("IMA: Measuring kernel structure: %s (%zu bytes)",
         structure_name, size);
    
    /* Calculate hash */
    res = optee_ima_measure(&ctx, hash);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    /* Set special UUID marker for kernel structures */
    ctx.uuid.timeLow = 0xFFFFFFFF;
    ctx.uuid.timeMid = 0xFFFF;
    ctx.uuid.timeHiAndVersion = 0xFFFF;
    memset(ctx.uuid.clockSeqAndNode, 0xFF, sizeof(ctx.uuid.clockSeqAndNode));
    
    /* Log to SML */
    res = optee_ima_log_event(&ctx, hash, IMA_ACTION_MEASURE, true);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    /* Extend kernel PCR */
    optee_ima_extend_pcr(IMA_PCR_KERNEL, hash);
    
    IMSG("IMA: Measured kernel structure '%s'", structure_name);
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * Compound Measurement Functions
 * =================================================================== */

TEE_Result optee_ima_measure_ta_complete(const TEE_UUID *uuid,
                                          const void *ta_binary,
                                          size_t ta_size,
                                          const struct ta_head *ta_header)
{
    TEE_Result res;
    uint8_t binary_hash[IMA_HASH_SIZE];
    uint8_t header_hash[IMA_HASH_SIZE];
    uint8_t compound_hash[IMA_HASH_SIZE];
    void *hash_ctx = NULL;
    
    if (!uuid || !ta_binary || ta_size == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    /* Measure TA binary */
    struct ima_event_context binary_ctx = {
        .event_type = EVENT_TYPE_TA_LOAD,
        .uuid = *uuid,
        .binary_data = ta_binary,
        .binary_data_len = ta_size
    };
    
    res = optee_ima_measure(&binary_ctx, binary_hash);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    /* Measure TA header if provided */
    if (ta_header) {
        struct ima_event_context header_ctx = {
            .event_type = EVENT_TYPE_TA_PROPERTIES_CHECK,
            .uuid = *uuid,
            .binary_data = ta_header,
            .binary_data_len = sizeof(*ta_header)
        };
        
        res = optee_ima_measure(&header_ctx, header_hash);
        if (res != TEE_SUCCESS) {
            return res;
        }
        
        /* Create compound measurement */
        res = crypto_hash_alloc_ctx(&hash_ctx, IMA_HASH_ALG);
        if (res != TEE_SUCCESS) {
            return res;
        }
        
        res = crypto_hash_init(hash_ctx);
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        /* Hash both measurements together */
        res = crypto_hash_update(hash_ctx, binary_hash, IMA_HASH_SIZE);
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        res = crypto_hash_update(hash_ctx, header_hash, IMA_HASH_SIZE);
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        res = crypto_hash_final(hash_ctx, compound_hash, IMA_HASH_SIZE);
        if (res != TEE_SUCCESS) {
            goto out;
        }
        
        DMSG("IMA: Created compound measurement for TA %pUl", (void *)uuid);
    }
    
out:
    if (hash_ctx) {
        crypto_hash_free_ctx(hash_ctx);
    }
    
    return res;
}

/* ===================================================================
 * Statistics and Debug
 * =================================================================== */

TEE_Result optee_ima_get_measurement_count(uint64_t *count)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_measurement_agent *agent = &ima_ctx->measurement_agent;
    
    if (!agent->initialized || !count) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&agent->lock);
    *count = agent->measurement_count;
    mutex_unlock(&agent->lock);
    
    return TEE_SUCCESS;
}

void optee_ima_reset_measurement_count(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_measurement_agent *agent = &ima_ctx->measurement_agent;
    
    if (!agent->initialized) {
        return;
    }
    
    mutex_lock(&agent->lock);
    agent->measurement_count = 0;
    mutex_unlock(&agent->lock);
    
    IMSG("IMA: Measurement count reset");
}
