/*
 * OP-TEE IMA Secure Measurement Log (SML)
 * Event logging and SML management
 * 
 * Copyright (c) 2024, OP-TEE IMA
 */

#include <kernel/optee_ima.h>
#include <crypto/crypto.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <stdio.h>

/* ===================================================================
 * Initialization and Cleanup
 * =================================================================== */

TEE_Result ima_log_init(struct ima_secure_log *sml)
{
    if (!sml) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
     
    //DMSG("IMA: Allocating Secure Measurement Log...");
    //DMSG("  Requested: %zu entries", (size_t)IMA_SML_MAX_ENTRIES);
    //DMSG("  Entry size: %zu bytes", sizeof(struct ima_log_entry));
    //DMSG("  Total size: %zu bytes (%zu KB)",
    //     IMA_SML_MAX_ENTRIES * sizeof(struct ima_log_entry),
    //     (IMA_SML_MAX_ENTRIES * sizeof(struct ima_log_entry)) / 1024);
    
    sml->entries = calloc(IMA_SML_MAX_ENTRIES, sizeof(struct ima_log_entry));
    if (!sml->entries) {
        EMSG("IMA: Failed to allocate SML");
        EMSG("     Requested: %zu bytes",
             IMA_SML_MAX_ENTRIES * sizeof(struct ima_log_entry));
        EMSG("     Available TZDRAM may be insufficient");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    sml->entry_count = 0;
    sml->max_entries = IMA_SML_MAX_ENTRIES;
    memset(sml->last_entry_hash, 0, IMA_HASH_SIZE);
    mutex_init(&sml->lock);
    sml->initialized = true;
    
    DMSG(" SML allocated at %p", (void *)sml->entries);
    
    return TEE_SUCCESS;
}

void ima_log_cleanup(struct ima_secure_log *sml)
{
    if (!sml || !sml->initialized) {
        return;
    }
    
    mutex_lock(&sml->lock);
    
    if (sml->entries) {
        free(sml->entries);
        sml->entries = NULL;
    }
    
    sml->entry_count = 0;
    sml->max_entries = 0;
    sml->initialized = false;
    
    mutex_unlock(&sml->lock);
    
    DMSG("IMA: SML cleaned up");
}

/* ===================================================================
 * Anti-Tampering Chain
 * =================================================================== */

static TEE_Result hash_sml_entry(const struct ima_log_entry *entry,
                                   uint8_t *hash_out)
{
    TEE_Result res;
    void *hash_ctx = NULL;
    
    res = crypto_hash_alloc_ctx(&hash_ctx, IMA_HASH_ALG);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    res = crypto_hash_init(hash_ctx);
    if (res != TEE_SUCCESS) {
        goto out;
    }
    
    /* Hash the complete entry including header and event data */
    res = crypto_hash_update(hash_ctx, (const uint8_t *)entry, entry->total_size);
    if (res != TEE_SUCCESS) {
        goto out;
    }
    
    res = crypto_hash_final(hash_ctx, hash_out, IMA_HASH_SIZE);

out:
    crypto_hash_free_ctx(hash_ctx);
    return res;
}

/* ===================================================================
 * Event Logging
 * =================================================================== */

TEE_Result optee_ima_log_event(const struct ima_event_context *ctx,
                                const uint8_t *hash,
                                enum ima_action action,
                                bool appraisal_result)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    struct ima_log_entry *entry;
    TEE_Result res;
    uint8_t pcr_index;
    
    if (!sml->initialized) {
        EMSG("IMA: SML not initialized");
        return TEE_ERROR_BAD_STATE;
    }
    
    if (!ctx || !hash) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&sml->lock);
    
    /* Check if SML is full */
    if (sml->entry_count >= sml->max_entries) {
        mutex_unlock(&sml->lock);
        EMSG("IMA: SML full (%zu entries)", sml->max_entries);
        return TEE_ERROR_OVERFLOW;
    }
    
    /* Get next entry slot */
    entry = &sml->entries[sml->entry_count];
    memset(entry, 0, sizeof(*entry));
    
    /* Determine PCR index based on event type */
    switch (ctx->event_type) {
    case EVENT_TYPE_KERNEL_BOOT:
        pcr_index = IMA_PCR_KERNEL;
        break;
    case EVENT_TYPE_STATIC_COMPONENT_LOAD:
        pcr_index = IMA_PCR_STATIC;
        break;
    case EVENT_TYPE_SYSCALL:
        pcr_index = IMA_PCR_SYSCALL;
        break;
    case EVENT_TYPE_TA_LOAD:
    case EVENT_TYPE_TA_PROPERTIES_CHECK:
        pcr_index = IMA_PCR_TA_DYNAMIC;
        break;
    default:
        pcr_index = IMA_PCR_TA_DYNAMIC;
    }
    
    /* Populate entry header */
    entry->header.pcr_index = pcr_index;
    entry->header.event_type = ctx->event_type;
    memcpy(entry->header.digest, hash, IMA_HASH_SIZE);
    
    /* Anti-tampering chain: link to previous entry */
    memcpy(entry->header.previous_entry_hash, sml->last_entry_hash, IMA_HASH_SIZE);
    
    /* Store event-specific data based on event type */
    switch (ctx->event_type) {
    case EVENT_TYPE_TA_LOAD:
        if (ctx->event_data && ctx->event_data_len >= sizeof(struct event_data_ta_load)) {
            memcpy(&entry->event_data.ta_load, ctx->event_data,
                   sizeof(struct event_data_ta_load));
            entry->header.event_data_size = sizeof(struct event_data_ta_load);
        }
        break;
        
    case EVENT_TYPE_TA_PROPERTIES_CHECK:
        if (ctx->event_data && ctx->event_data_len >= sizeof(struct event_data_ta_properties)) {
            memcpy(&entry->event_data.ta_props, ctx->event_data,
                   sizeof(struct event_data_ta_properties));
            entry->header.event_data_size = sizeof(struct event_data_ta_properties);
        }
        break;
        
    case EVENT_TYPE_SYSCALL:
        if (ctx->event_data && ctx->event_data_len > 0) {
            size_t copy_size = MIN(ctx->event_data_len, sizeof(entry->event_data.raw_data));
            memcpy(&entry->event_data.syscall, ctx->event_data, copy_size);
            entry->header.event_data_size = copy_size;
        }
        break;
        
    case EVENT_TYPE_KERNEL_BOOT:
    case EVENT_TYPE_STATIC_COMPONENT_LOAD:
        /* These events typically don't have additional data */
        entry->header.event_data_size = 0;
        break;
        
    default:
        entry->header.event_data_size = 0;
    }
    
    /* Calculate total entry size */
    entry->total_size = sizeof(entry->header) + entry->header.event_data_size;
    entry->appraisal_result = appraisal_result;
    entry->action = action;
    
    /* Update anti-tampering chain hash */
    res = hash_sml_entry(entry, sml->last_entry_hash);
    if (res != TEE_SUCCESS) {
        EMSG("IMA: Failed to hash SML entry: 0x%08x", res);
        mutex_unlock(&sml->lock);
        return res;
    }
    
    /* Increment entry count */
    sml->entry_count++;
    
    mutex_unlock(&sml->lock);
    
    DMSG("IMA: Logged event #%zu (type=%d, PCR=%d, action=%d, result=%s)",
         sml->entry_count - 1, ctx->event_type, pcr_index, action,
         appraisal_result ? "PASS" : "FAIL");
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * SML Export
 * =================================================================== */

TEE_Result optee_ima_export_sml(void *buffer, size_t *buffer_len)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    size_t required_size = 0;
    uint8_t *dst = buffer;
    
    if (!sml->initialized) {
        return TEE_ERROR_BAD_STATE;
    }
    
    if (!buffer_len) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&sml->lock);
    
    /* Calculate required buffer size */
    for (size_t i = 0; i < sml->entry_count; i++) {
        required_size += sml->entries[i].total_size;
    }
    
    /* Check buffer size */
    if (!buffer || *buffer_len < required_size) {
        *buffer_len = required_size;
        mutex_unlock(&sml->lock);
        return buffer ? TEE_ERROR_SHORT_BUFFER : TEE_SUCCESS;
    }
    
    /* Copy entries to buffer */
    for (size_t i = 0; i < sml->entry_count; i++) {
        struct ima_log_entry *entry = &sml->entries[i];
        memcpy(dst, entry, entry->total_size);
        dst += entry->total_size;
    }
    
    *buffer_len = required_size;
    mutex_unlock(&sml->lock);
    
    IMSG("IMA: Exported SML (%zu entries, %zu bytes)", 
         sml->entry_count, required_size);
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * SML Verification
 * =================================================================== */

TEE_Result optee_ima_verify_sml_chain(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    uint8_t computed_hash[IMA_HASH_SIZE];
    uint8_t expected_hash[IMA_HASH_SIZE];
    TEE_Result res;
    bool chain_valid = true;
    
    if (!sml->initialized || sml->entry_count == 0) {
        return TEE_SUCCESS;  /* Nothing to verify */
    }
    
    mutex_lock(&sml->lock);
    
    /* Initialize expected hash to zero (first entry should have zeros) */
    memset(expected_hash, 0, IMA_HASH_SIZE);
    
    /* Verify each entry in the chain */
    for (size_t i = 0; i < sml->entry_count; i++) {
        struct ima_log_entry *entry = &sml->entries[i];
        
        /* Check if previous hash matches */
        if (memcmp(entry->header.previous_entry_hash, expected_hash, IMA_HASH_SIZE) != 0) {
            EMSG("IMA: Chain broken at entry %zu", i);
            chain_valid = false;
            break;
        }
        
        /* Compute hash of current entry */
        res = hash_sml_entry(entry, computed_hash);
        if (res != TEE_SUCCESS) {
            EMSG("IMA: Failed to hash entry %zu", i);
            chain_valid = false;
            break;
        }
        
        /* This becomes the expected hash for next entry */
        memcpy(expected_hash, computed_hash, IMA_HASH_SIZE);
    }
    
    /* Final hash should match last_entry_hash */
    if (chain_valid && 
        memcmp(expected_hash, sml->last_entry_hash, IMA_HASH_SIZE) != 0) {
        EMSG("IMA: Final hash mismatch in SML chain");
        chain_valid = false;
    }
    
    mutex_unlock(&sml->lock);
    
    if (chain_valid) {
        IMSG("IMA: SML chain verification PASSED");
        return TEE_SUCCESS;
    } else {
        EMSG("IMA: SML chain verification FAILED");
        return TEE_ERROR_SECURITY;
    }
}

/* ===================================================================
 * SML Query Functions
 * =================================================================== */

TEE_Result optee_ima_get_sml_entry(size_t index, struct ima_log_entry *entry_out)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    
    if (!sml->initialized || !entry_out) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&sml->lock);
    
    if (index >= sml->entry_count) {
        mutex_unlock(&sml->lock);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    
    memcpy(entry_out, &sml->entries[index], sizeof(*entry_out));
    
    mutex_unlock(&sml->lock);
    
    return TEE_SUCCESS;
}

TEE_Result optee_ima_get_sml_count(size_t *count)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    
    if (!sml->initialized || !count) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&sml->lock);
    *count = sml->entry_count;
    mutex_unlock(&sml->lock);
    
    return TEE_SUCCESS;
}

TEE_Result optee_ima_clear_sml(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    
    if (!sml->initialized) {
        return TEE_ERROR_BAD_STATE;
    }
    
    mutex_lock(&sml->lock);
    
    /* Clear all entries */
    memset(sml->entries, 0, sml->max_entries * sizeof(struct ima_log_entry));
    sml->entry_count = 0;
    memset(sml->last_entry_hash, 0, IMA_HASH_SIZE);
    
    mutex_unlock(&sml->lock);
    
    IMSG("IMA: SML cleared");
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * Debug Functions
 * =================================================================== */

void optee_ima_dump_sml(int start, int end)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    struct ima_log_entry *entry;
    char hash_hex[IMA_HASH_SIZE * 2 + 1];
    const char *event_names[] = {
        "KERNEL_BOOT", "STATIC_LOAD", "TA_LOAD", "TA_PROPS", "SYSCALL"
    };
    const char *action_names[] = {
        "MEASURE", "APPRAISE", "DONT_MEASURE", "DONT_APPRAISE"
    };
    
    if (!sml->initialized) {
        EMSG("IMA: SML not initialized");
        return;
    }
    
    IMSG("========================================");
    IMSG("IMA Secure Measurement Log (SML)");
    IMSG("========================================");
    IMSG("Total entries: %zu / %zu", sml->entry_count, sml->max_entries);
    IMSG("Memory usage:  %zu KB",
         (sml->entry_count * sizeof(struct ima_log_entry)) / 1024);
    IMSG("========================================");
    
    if (sml->entry_count == 0) {
        IMSG("SML is empty - no events recorded yet");
        IMSG("========================================");
        return;
    }
    
    mutex_lock(&sml->lock);
    
    //for (size_t i = 0; i < sml->entry_count && i < 10; i++) {  /* Limit output */
    //for (size_t i = 5; i < sml->entry_count && i < 15; i++) {  /* Limit output */
    for (size_t i = start; i < sml->entry_count && i < end; i++) {  /* Limit output */
        entry = &sml->entries[i];
        
        /* Convert hash to hex (first 8 bytes only for display) */
        for (size_t j = 0; j < 8 && j < IMA_HASH_SIZE; j++) {
            snprintf(&hash_hex[j*2], 3, "%02x", entry->header.digest[j]);
        }
        hash_hex[16] = '\0';
        
        IMSG("");
        IMSG("Entry #%04zu:", i);
        IMSG("  PCR:        %u", entry->header.pcr_index);
        IMSG("  Event:      %s", 
             entry->header.event_type < EVENT_TYPE_MAX ? 
             event_names[entry->header.event_type] : "UNKNOWN");
        IMSG("  Action:     %s",
             entry->action < IMA_ACTION_MAX ?
             action_names[entry->action] : "UNKNOWN");
        IMSG("  Result:     %s", entry->appraisal_result ? "PASS" : "FAIL");
        IMSG("  Hash:       %s...", hash_hex);
        
        /* Print event-specific data */
        switch (entry->header.event_type) {
        case EVENT_TYPE_TA_LOAD:
            IMSG("  TA UUID:    %pUl (v%u)",
                 (void *)&entry->event_data.ta_load.ta_uuid,
                 entry->event_data.ta_load.ta_version);
            break;
            
        case EVENT_TYPE_TA_PROPERTIES_CHECK:
            IMSG("  TA UUID:    %pUl",
                 (void *)&entry->event_data.ta_props.ta_uuid);
            IMSG("  Flags:      0x%08x", entry->event_data.ta_props.ta_flags);
            IMSG("  Stack:      %u bytes", entry->event_data.ta_props.ta_stack_size);
            IMSG("  Data:       %u bytes", entry->event_data.ta_props.ta_data_size);
            break;
        /*    
        case EVENT_TYPE_SYSCALL:
            IMSG("  Caller:     %pUl",
                 (void *)&entry->event_data.syscall.caller_uuid);
            IMSG("  Syscall:    0x%08x", entry->event_data.syscall.syscall_id);
            IMSG("  Result:     0x%08x", entry->event_data.syscall.result);
            break;
        */
        case EVENT_TYPE_SYSCALL:
            IMSG("  Caller:     %pUl",
                 (void *)&entry->event_data.syscall.caller_uuid);
            IMSG("  Syscall:    0x%08x", entry->event_data.syscall.syscall_id);
            
            /* Special handling for TA invocation syscalls */
            if (entry->event_data.syscall.syscall_id == 0x00000402 ||
                entry->event_data.syscall.syscall_id == 0x00000104) {
                
                /* Extract invoke_ta_command params from the syscall data */
                const uint8_t *syscall_data = 
                    ((const uint8_t *)&entry->event_data.syscall) + 
                    sizeof(struct event_data_syscall);
                
                const struct syscall_params_invoke_ta *invoke_params =
                    (const struct syscall_params_invoke_ta_command *)syscall_data;
                
                const char *type = (entry->event_data.syscall.syscall_id == 0x00000402) ?
                                   "TA-to-TA" : "CA-to-TA";
                
                IMSG("  Type:       %s Invocation", type);
                IMSG("  Target TA:  %pUl", (void *)&invoke_params->target_uuid);
                
                if (entry->event_data.syscall.syscall_id == 0x00000402) {
                    IMSG("  Caller TA:  %pUl", (void *)&invoke_params->caller_uuid);
                }
                
                IMSG("  Command:    %u", invoke_params->command_id);
                IMSG("  Param Type: 0x%08x", invoke_params->param_types);
                
                /* Display before/after hash comparison */
                char before_str[17], after_str[17];
                for (size_t j = 0; j < 8; j++) {
                    snprintf(&before_str[j*2], 3, "%02x", 
                             invoke_params->before_param_hash[j]);
                    snprintf(&after_str[j*2], 3, "%02x", 
                             invoke_params->after_param_hash[j]);
                }
                before_str[16] = '\0';
                after_str[16] = '\0';
                
                IMSG("  Before:     %s...", before_str);
                IMSG("  After:      %s...", after_str);
                
                if (memcmp(invoke_params->before_param_hash,
                          invoke_params->after_param_hash,
                          IMA_HASH_SIZE) != 0) {
                    IMSG(" MODIFIED: Parameters changed during invocation");
                }
            }
            
            IMSG("  Result:     0x%08x", entry->event_data.syscall.result);
            break;
        default:
            break;
        }
        
        /* Show chain linkage status */
        if (i > 0) {
            IMSG("  Chain:      Linked to entry #%04zu", i - 1);
        } else {
            IMSG("  Chain:      Genesis entry");
        }
    }
    
    if (sml->entry_count > (end - start - 1)) {
        IMSG("");
        IMSG("... %zu more entries ...", 
             sml->entry_count - (end - start - 1));
    }
    
    mutex_unlock(&sml->lock);
    
    /* Verify chain integrity */
    TEE_Result res = optee_ima_verify_sml_chain();
    
    IMSG("");
    IMSG("Chain Integrity: %s",
         res == TEE_SUCCESS ? "VALID" : "BROKEN");
    
    IMSG("");
    IMSG("========================================");
    IMSG("End of SML Dump");
    IMSG("========================================");
}

void optee_ima_dump_sml_stats(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_secure_log *sml = &ima_ctx->sml;
    size_t event_counts[EVENT_TYPE_MAX] = {0};
    size_t action_counts[IMA_ACTION_MAX] = {0};
    size_t pass_count = 0, fail_count = 0;
    
    if (!sml->initialized) {
        return;
    }
    
    mutex_lock(&sml->lock);
    
    /* Gather statistics */
    for (size_t i = 0; i < sml->entry_count; i++) {
        struct ima_log_entry *entry = &sml->entries[i];
        
        if (entry->header.event_type < EVENT_TYPE_MAX) {
            event_counts[entry->header.event_type]++;
        }
        
        if (entry->action < IMA_ACTION_MAX) {
            action_counts[entry->action]++;
        }
        
        if (entry->appraisal_result) {
            pass_count++;
        } else {
            fail_count++;
        }
    }
    
    mutex_unlock(&sml->lock);
    
    IMSG("========================================");
    IMSG("SML Statistics");
    IMSG("========================================");
    IMSG("Event Types:");
    IMSG("  Kernel Boot:    %zu", event_counts[EVENT_TYPE_KERNEL_BOOT]);
    IMSG("  Static Load:    %zu", event_counts[EVENT_TYPE_STATIC_COMPONENT_LOAD]);
    IMSG("  TA Load:        %zu", event_counts[EVENT_TYPE_TA_LOAD]);
    IMSG("  TA Properties:  %zu", event_counts[EVENT_TYPE_TA_PROPERTIES_CHECK]);
    IMSG("  Syscalls:       %zu", event_counts[EVENT_TYPE_SYSCALL]);
    IMSG("");
    IMSG("Actions:");
    IMSG("  Measure:        %zu", action_counts[IMA_ACTION_MEASURE]);
    IMSG("  Appraise:       %zu", action_counts[IMA_ACTION_APPRAISE]);
    IMSG("");
    IMSG("Appraisal Results:");
    IMSG("  Passed:         %zu", pass_count);
    IMSG("  Failed:         %zu", fail_count);
    IMSG("  Success Rate:   %zu%%",
         (pass_count + fail_count) > 0 ?
         (pass_count * 100) / (pass_count + fail_count) : 0);
    IMSG("========================================");
}
