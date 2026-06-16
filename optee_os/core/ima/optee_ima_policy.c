/*
 * OP-TEE IMA Policy Management
 * Policy parsing, evaluation, and rule management
 * 
 * Copyright (c) 2024, OP-TEE IMA
 */

#include <kernel/optee_ima.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <trace.h>
#include <utee_types.h>

/* External symbols from build system */
extern const char _binary_ima_policy_start[];
extern const char *_binary_ima_policy_end;

/* Action and event type strings for parsing */
static const char *action_strings[] = {
    "measure", "appraise", "dont_measure", "dont_appraise"
};

static const char *event_type_strings[] = {
    "KERNEL_BOOT", "STATIC_COMPONENT_LOAD", "TA_LOAD",
    "TA_PROPERTIES_CHECK", "SYSCALL", "TA_COMMAND_INVOKE", "PERIODIC_KERNEL_CHECK"
};

/* ===================================================================
 * OP-TEE Compatible
 * =================================================================== */

static bool uuid_equal(const TEE_UUID *a, const TEE_UUID *b)
{
    return memcmp(a, b, sizeof(TEE_UUID)) == 0;
}

/**
 * Simple string to unsigned long conversion for OP-TEE
 * Supports decimal and hexadecimal (0x prefix)
 */
static unsigned long simple_strtoul(const char *str, char **endptr, int base)
{
    unsigned long result = 0;
    bool negative = false;
    
    /* Skip whitespace */
    while (*str == ' ' || *str == '\t') str++;
    
    /* Check sign */
    if (*str == '-') {
        negative = true;
        str++;
    } else if (*str == '+') {
        str++;
    }
    
    /* Determine base */
    if (base == 0) {
        if (*str == '0') {
            str++;
            if (*str == 'x' || *str == 'X') {
                base = 16;
                str++;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    }
    
    /* Convert digits */
    while (*str) {
        unsigned int digit;
        
        if (*str >= '0' && *str <= '9') {
            digit = *str - '0';
        } else if (*str >= 'a' && *str <= 'f') {
            digit = *str - 'a' + 10;
        } else if (*str >= 'A' && *str <= 'F') {
            digit = *str - 'A' + 10;
        } else {
            break;
        }
        
        if (digit >= (unsigned int)base) {
            break;
        }
        
        result = result * base + digit;
        str++;
    }
    
    if (endptr) {
        *endptr = (char *)str;
    }
    
    return negative ? -result : result;
}

static TEE_Result parse_uuid(const char *str, TEE_UUID *uuid) {
    const char *p = str;
    unsigned long long parts[5];
    int i;
    
    /* Parse 8-4-4-4-12 format */
    for (i = 0; i < 5; i++) {
        unsigned long long val = 0;
        int digits = (i == 4) ? 12 : (i == 0 ? 8 : 4);
        int j;
        
        for (j = 0; j < digits; j++) {
            char c = *p++;
            unsigned int digit;
            
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            } else {
                return TEE_ERROR_BAD_FORMAT;
            }
            
            val = (val << 4) | digit;
        }
        
        parts[i] = val;
        
        /* Check separator (dash) except for last part */
        if (i < 4) {
            if (*p != '-') {
                return TEE_ERROR_BAD_FORMAT;
            }
            p++;
        }
    }
    
    /* Check for end of string */
    if (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
        return TEE_ERROR_BAD_FORMAT;
    }
    
    /* Convert to TEE_UUID structure */
    uuid->timeLow = parts[0];
    uuid->timeMid = parts[1];
    uuid->timeHiAndVersion = parts[2];
    
    /* parts[3] forms clockSeqAndNode[0..1] */
    uuid->clockSeqAndNode[0] = (parts[3] >> 8) & 0xFF;
    uuid->clockSeqAndNode[1] = parts[3] & 0xFF;
    
    /* parts[4] forms clockSeqAndNode[2..7] */
    for (i = 0; i < 6; i++) {
        uuid->clockSeqAndNode[2 + i] = (parts[4] >> ((5 - i) * 8)) & 0xFF;
    }
    
    return TEE_SUCCESS;
}

/**
 * Extract next token from string
 */
static const char *next_token(const char *str, char *buf, size_t buf_size)
{
    const char *p = str;
    size_t len = 0;
    
    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;
    
    /* Copy until whitespace or end */
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
        if (len < buf_size - 1) {
            buf[len++] = *p;
        }
        p++;
    }
    
    buf[len] = '\0';
    return p;
}

/**
 * Parse key=value pair without using sscanf
 */
static bool parse_key_value(const char *str, char *key, size_t key_size, 
                           char *value, size_t value_size)
{
    const char *equal = strchr(str, '=');
    
    if (!equal) {
        return false;
    }
    
    /* Extract key */
    size_t key_len = equal - str;
    if (key_len >= key_size) {
        key_len = key_size - 1;
    }
    memcpy(key, str, key_len);
    key[key_len] = '\0';
    
    /* Extract value */
    const char *val_start = equal + 1;
    const char *p = val_start;
    size_t val_len = 0;
    
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
        if (val_len < value_size - 1) {
            value[val_len++] = *p;
        }
        p++;
    }
    
    value[val_len] = '\0';
    return true;
}

/* ===================================================================
 * Policy Parsing
 * =================================================================== */

static TEE_Result parse_policy_line(const char *line,
                                     struct ima_policy_rule **rule_out)
{
    struct ima_policy_rule *rule;
    char action_str[32], cond_key[64], cond_val[128];
    const char *ptr = line;
    int i;
    
    /* Skip whitespace */
    while (*ptr == ' ' || *ptr == '\t') ptr++;
    
    /* Skip comments and empty lines */
    if (*ptr == '#' || *ptr == '\0' || *ptr == '\n') {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    
    /* Allocate new rule */
    rule = calloc(1, sizeof(*rule));
    if (!rule) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    /* Parse action using custom tokenizer */
    ptr = next_token(ptr, action_str, sizeof(action_str));
    
    /* Match action string */
    for (i = 0; i < IMA_ACTION_MAX; i++) {
        if (strcmp(action_str, action_strings[i]) == 0) {
            rule->action = i;
            break;
        }
    }
    
    if (i == IMA_ACTION_MAX) {
        DMSG("IMA: Unknown action: %s", action_str);
        goto err;
    }
    
    /* Parse conditions */
    while (*ptr) {
        /* Skip whitespace */
        while (*ptr == ' ' || *ptr == '\t') ptr++;
        if (*ptr == '\0' || *ptr == '\n') break;
        
        /* Parse key=value pair using custom parser */
        if (parse_key_value(ptr, cond_key, sizeof(cond_key), 
                           cond_val, sizeof(cond_val))) {
            if (strcmp(cond_key, "event_type") == 0) {
                /* Match event type */
                for (i = 0; i < EVENT_TYPE_MAX; i++) {
                    if (strcmp(cond_val, event_type_strings[i]) == 0) {
                        rule->event_type = i;
                        rule->condition_mask |= IMA_COND_EVENT_TYPE;
                        break;
                    }
                }
                if (i == EVENT_TYPE_MAX) {
                    DMSG("IMA: Unknown event type: %s", cond_val);
                }
            } else if (strcmp(cond_key, "uuid") == 0) {
                if (parse_uuid(cond_val, &rule->uuid) == TEE_SUCCESS) {
                    rule->condition_mask |= IMA_COND_UUID;
                } else {
                    DMSG("IMA: Invalid UUID format: %s", cond_val);
                }
            } else if (strcmp(cond_key, "syscall_id") == 0) {
                /* Use custom strtoul replacement */
                rule->syscall_id = simple_strtoul(cond_val, NULL, 0);
                rule->condition_mask |= IMA_COND_SYSCALL_ID;
            } else if (strcmp(cond_key, "command_id") == 0) {
                /* Parse command_id for TA_COMMAND_INVOKE events */
                rule->command_id = simple_strtoul(cond_val, NULL, 0);
                rule->condition_mask |= IMA_COND_COMMAND_ID;
                DMSG("IMA: Policy: Added condition command_id=0x%08x", rule->command_id);
            } else if (strcmp(cond_key, "target_uuid") == 0) {
                if (parse_uuid(cond_val, &rule->target_uuid) == TEE_SUCCESS) {
                    rule->condition_mask |= IMA_COND_TARGET_UUID;
                } else {
                    DMSG("IMA: Invalid target UUID format: %s", cond_val);
                }
            } else if (strcmp(cond_key, "interval") == 0) {
                rule->interval_ms = simple_strtoul(cond_val, NULL, 10);
                rule->condition_mask |= IMA_COND_INTERVAL;
                DMSG("IMA: Parsed interval=%u ms", rule->interval_ms);
            } else {
                DMSG("IMA: Unknown condition: %s", cond_key);
            }
            
            /* Move to next token */
            ptr += strlen(cond_key) + 1 + strlen(cond_val);
        } else {
            /* Invalid key=value format, skip to next space */
            const char *next_space = ptr;
            while (*next_space && *next_space != ' ' && *next_space != '\t') {
                next_space++;
            }
            ptr = next_space;
        }
    }
    
    *rule_out = rule;
    return TEE_SUCCESS;

err:
    free(rule);
    return TEE_ERROR_BAD_FORMAT;
}

/* ===================================================================
 * Policy Loading
 * =================================================================== */

TEE_Result ima_policy_load_embedded(struct ima_policy_manager *mgr)
{
    const char *policy_start = _binary_ima_policy_start;
    const char *policy_end = _binary_ima_policy_end;
    const char *line_start, *line_end;
    struct ima_policy_rule *rule, *tail = NULL;
    TEE_Result res;
    char line_buf[256];
    size_t policy_size;
    uint32_t rule_count = 0;
    
    if (!policy_start || policy_start >= policy_end) {
        EMSG("IMA: No embedded policy found");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    
    policy_size = (size_t)(policy_end - policy_start);
    
    /*
    IMSG("========================================");
    IMSG("IMA: Loading Embedded Policy");
    IMSG("========================================");
    IMSG("Policy start address: %p", (void *)policy_start);
    IMSG("Policy end address:   %p", (void *)policy_end);
    IMSG("Policy size:          %zu bytes", policy_size);
    IMSG("----------------------------------------");
    
#ifdef IMA_DEBUG
    DMSG("Raw policy content:");
    const char *p = policy_start;
    size_t line_num = 1;
    const char *line_begin = p;
    
    while (p < policy_end) {
        if (*p == '\n' || p == policy_end - 1) {
            size_t line_len = p - line_begin + (p == policy_end - 1 ? 1 : 0);
            if (line_len > 0 && line_len < sizeof(line_buf)) {
                memcpy(line_buf, line_begin, line_len);
                line_buf[line_len] = '\0';
                
                bool has_content = false;
                for (size_t i = 0; i < line_len; i++) {
                    if (line_buf[i] != ' ' && line_buf[i] != '\t' && 
                        line_buf[i] != '\n' && line_buf[i] != '\r') {
                        has_content = true;
                        break;
                    }
                }
                
                if (has_content) {
                    DMSG("[%03zu] %s", line_num, line_buf);
                }
            }
            line_begin = p + 1;
            line_num++;
        }
        p++;
    }
    DMSG("Total lines: %zu", line_num - 1);
    DMSG("----------------------------------------");
#endif
*/    
    /* Parse policy line by line */
    line_start = policy_start;
    
    while (line_start < policy_end) {
        /* Find line end */
        line_end = line_start;
        while (line_end < policy_end && *line_end != '\n')
            line_end++;
        
        /* Copy line to buffer */
        size_t line_len = MIN(line_end - line_start, sizeof(line_buf) - 1);
        memcpy(line_buf, line_start, line_len);
        line_buf[line_len] = '\0';
        
        /* Parse line */
        res = parse_policy_line(line_buf, &rule);
        if (res == TEE_SUCCESS) {
            /* Add rule to chain */
            if (!mgr->rules)
                mgr->rules = rule;
            else
                tail->next = rule;
            tail = rule;
            rule_count++;
            
            /* Print parsed rule details */
            /*
            IMSG("Rule #%u: %s", rule_count, action_strings[rule->action]);
            
            if (rule->condition_mask & IMA_COND_EVENT_TYPE) {
                IMSG("  event_type=%s", event_type_strings[rule->event_type]);
            }
            
            if (rule->condition_mask & IMA_COND_UUID) {
                IMSG("  uuid=%pUl", (void *)&rule->uuid);
            }
            
            if (rule->condition_mask & IMA_COND_SYSCALL_ID) {
                IMSG("  syscall_id=0x%08x", rule->syscall_id);
            }
            
            if (rule->condition_mask & IMA_COND_TARGET_UUID) {
                IMSG("  target_uuid=%pUl", (void *)&rule->target_uuid);
            }
            */
        } else if (res == TEE_ERROR_BAD_FORMAT) {
            // Only warn about parsing errors for non-empty lines
            bool is_empty = true;
            for (size_t i = 0; i < line_len; i++) {
                if (line_buf[i] != ' ' && line_buf[i] != '\t' && 
                    line_buf[i] != '\n' && line_buf[i] != '\r') {
                    is_empty = false;
                    break;
                }
            }
            
            if (!is_empty && line_buf[0] != '#') {
                EMSG("Failed to parse policy line: %s", line_buf);
            }
        }
        
        line_start = line_end + 1;
    }
    
    mgr->initialized = true;
    mgr->embedded_policy = policy_start;
    
    /*
    IMSG("----------------------------------------");
    IMSG("Policy loaded successfully:");
    IMSG("  Total rules: %u", rule_count);
    IMSG("  Policy size: %zu bytes", policy_size);
    IMSG("========================================");
    */
    if (rule_count == 0) {
        EMSG("WARNING: No valid policy rules loaded!");
        EMSG("         IMA will not enforce any measurements");
    }
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * Policy Evaluation
 * =================================================================== */

static bool rule_matches(const struct ima_policy_rule *rule,
                          const struct ima_event_context *ctx)
{  
    /* Check event_type condition */
    if ((rule->condition_mask & IMA_COND_EVENT_TYPE) &&
        rule->event_type != ctx->event_type) {
        return false;
    }
    
    /* Check UUID condition */
    if ((rule->condition_mask & IMA_COND_UUID) &&
        !uuid_equal(&rule->uuid, &ctx->uuid)) {
        return false;
    }
    
    /* Check syscall_id condition */
    if ((rule->condition_mask & IMA_COND_SYSCALL_ID) &&
        rule->syscall_id != ctx->syscall_id) {
        return false;
    }
    
    /* Check target_uuid condition */
    if ((rule->condition_mask & IMA_COND_TARGET_UUID) &&
        !uuid_equal(&rule->target_uuid, &ctx->target_uuid)) {
        return false;
    }
    
    /* Check command_id condition */
    if ((rule->condition_mask & IMA_COND_COMMAND_ID) &&
        rule->command_id != ctx->syscall_id) {  /* Reuse the syscall_id field to store the command_id */
        return false;
    }
    
    /* All conditions match */
    return true;
}

TEE_Result optee_ima_evaluate_policy(const struct ima_event_context *ctx,
                                      enum ima_action *action_out)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_policy_manager *mgr = &ima_ctx->policy_mgr;
    struct ima_policy_rule *rule;
    enum ima_action action = IMA_ACTION_DONT_MEASURE;  /* Default: no action */
    
    if (!mgr->initialized) {
        EMSG("IMA: Policy not initialized");
        return TEE_ERROR_BAD_STATE;
    }
    
    if (!ctx || !action_out) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&mgr->lock);
    
    /* Evaluate rules - first match wins */
    for (rule = mgr->rules; rule; rule = rule->next) {
        if (rule_matches(rule, ctx)) {
            action = rule->action;
            DMSG("IMA: Policy match - action=%s for event=%d",
                 action_strings[action], ctx->event_type);
            break;
        }
    }
    
    /* No match - use default action */
    if (!rule) {
        DMSG("IMA: No policy match - using default (DONT_MEASURE)");
    }
    
    mutex_unlock(&mgr->lock);
    
    *action_out = action;
    return TEE_SUCCESS;
}

/* ===================================================================
 * Policy Management
 * =================================================================== */

TEE_Result optee_ima_add_policy_rule(struct ima_policy_rule *new_rule)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_policy_manager *mgr = &ima_ctx->policy_mgr;
    struct ima_policy_rule *rule, *tail = NULL;
    
    if (!new_rule) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mutex_lock(&mgr->lock);
    
    /* Find end of rule chain */
    for (rule = mgr->rules; rule; rule = rule->next) {
        tail = rule;
    }
    
    /* Add new rule */
    if (tail) {
        tail->next = new_rule;
    } else {
        mgr->rules = new_rule;
    }
    
    new_rule->next = NULL;
    
    mutex_unlock(&mgr->lock);
    
    IMSG("IMA: Added policy rule - action=%s",
         action_strings[new_rule->action]);
    
    return TEE_SUCCESS;
}

TEE_Result optee_ima_clear_policy(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_policy_manager *mgr = &ima_ctx->policy_mgr;
    struct ima_policy_rule *rule, *next;
    
    mutex_lock(&mgr->lock);
    
    /* Free all rules */
    rule = mgr->rules;
    while (rule) {
        next = rule->next;
        free(rule);
        rule = next;
    }
    
    mgr->rules = NULL;
    mgr->initialized = false;
    
    mutex_unlock(&mgr->lock);
    
    IMSG("IMA: Policy cleared");
    
    return TEE_SUCCESS;
}

/* ===================================================================
 * Debug Functions
 * =================================================================== */

void optee_ima_dump_policy(void)
{
    struct optee_ima_context *ima_ctx = &g_ima_ctx;
    struct ima_policy_manager *mgr = &ima_ctx->policy_mgr;
    struct ima_policy_rule *rule;
    uint32_t rule_count = 0;
    
    if (!mgr->initialized) {
        EMSG("IMA: Policy not initialized");
        return;
    }
    
    IMSG("========================================");
    IMSG("IMA Policy Rules");
    IMSG("========================================");
    
    mutex_lock(&mgr->lock);
    
    for (rule = mgr->rules; rule; rule = rule->next) {
        rule_count++;
        
        IMSG("");
        IMSG("Rule #%u:", rule_count);
        IMSG("  Action:     %s", action_strings[rule->action]);
        IMSG("  Conditions: 0x%08x", rule->condition_mask);
        
        if (rule->condition_mask & IMA_COND_EVENT_TYPE) {
            IMSG("  Event Type: %s", event_type_strings[rule->event_type]);
        }
        
        if (rule->condition_mask & IMA_COND_UUID) {
            IMSG("  UUID:       %pUl", (void *)&rule->uuid);
        }
        
        if (rule->condition_mask & IMA_COND_SYSCALL_ID) {
            IMSG("  Syscall ID: 0x%08x", rule->syscall_id);
        }
        
        if (rule->condition_mask & IMA_COND_TARGET_UUID) {
            IMSG("  Target:     %pUl", (void *)&rule->target_uuid);
        }
    }
    
    mutex_unlock(&mgr->lock);
    
    IMSG("");
    IMSG("========================================");
    IMSG("Total Policy Rules: %u", rule_count);
    IMSG("========================================");
}
