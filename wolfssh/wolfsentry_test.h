/* wolfsentry_test.h
 *
 * Copyright (C) 2014-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _WOLFSENTRY_TEST_H_
#define _WOLFSENTRY_TEST_H_

#include <time.h>

static char wolfsentry_hook_verbose = 1;

#define PRINT_DATE(c, s) print_sentry_time_2_date(c,s);
/**
 *  Convert wolfsentry time to human readable date/time
 * @param sentry the wolfsentry object
 * @param s  wolfsentry time 
 *
 * @return none
 */
static void print_sentry_time_2_date(struct wolfsentry_context *sentry,
                                        wolfsentry_time_t s)
{
    char date[64] = {0};
    long epoch;
    long epoch_nan;

    if (s == 0) {
        printf("\n");
        return;
    }
    /* convert wolfsentry time to epoch time */
    wolfsentry_to_epoch_time(sentry, s, &epoch, &epoch_nan);

    ctime_r(&epoch, date);
    printf("%s", date);
}
/**
 * Callback function when authentication succeeded
 *
 * @return 1 for successful, otherwise wolfsentry error code
 */
static wolfsentry_errcode_t auth_succeed_action(
    struct wolfsentry_context *sentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    int ret = 0;
    const struct wolfsentry_event *parent_event = 
                                    wolfsentry_route_parent_event(rule_route);
    (void)sentry;
    (void)handler_arg;
    (void)route_table;
    (void)action_results;
    (void)target_route;
    (void)action_type;

    fprintf(stderr, "action callback: a=\"%s\" parent_event=\"%s\" "
                                "trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
            wolfsentry_action_get_label(action),
            wolfsentry_event_get_label(parent_event),
            wolfsentry_event_get_label(trigger_event),
            action_type,
            wolfsentry_get_object_id(rule_route),
            caller_arg);
    fprintf(stderr, "Succeed password authentication :\n");
    if (rule_route) {

        fprintf(stderr, "Route detail: \n");
        wolfsentry_route_render(wolfsentry, rule_route, stdout);
        
        struct wolfsentry_route_metadata_exports metadata;
        wolfsentry_route_get_metadata(rule_route, &metadata);

        fprintf(stderr, " insert_time \t\t");  PRINT_DATE(sentry,
                                                metadata.insert_time);
        fprintf(stderr, " last_hit_time \t\t"); PRINT_DATE(sentry,
                                               metadata.last_hit_time);
        fprintf(stderr, " last_penaltybox_time \t"); PRINT_DATE(sentry,
                                                metadata.last_penaltybox_time);
        fprintf(stderr, " connection_count \t%d\n", metadata.connection_count);
        fprintf(stderr, " derogatory_count \t%d\n", metadata.derogatory_count);
        fprintf(stderr, " commendable_count \t%d\n", metadata.commendable_count);

        fprintf(stderr, "\n");

    }
    return ret;
}
/**
 * Callback function when authentication failed
 *
 * @return 0 for successful, otherwise wolfsentry error code
 */
static wolfsentry_errcode_t auth_failed_action(
    struct wolfsentry_context *sentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event = 
                                    wolfsentry_route_parent_event(rule_route);
    (void)sentry;
    (void)handler_arg;
    (void)route_table;
    (void)action_results;
    (void)target_route;
    (void)action_type;
    
    fprintf(stderr, "action callback: a=\"%s\" parent_event=\"%s\" "
                                "trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
            wolfsentry_action_get_label(action),
            wolfsentry_event_get_label(parent_event),
            wolfsentry_event_get_label(trigger_event),
            action_type,
            wolfsentry_get_object_id(rule_route),
            caller_arg);

    fprintf(stderr, "Failed password authentication :\n");
    if (rule_route) {

        fprintf(stderr, "Route detail: \n");
        wolfsentry_route_render(wolfsentry, rule_route, stdout);
        
        struct wolfsentry_route_metadata_exports metadata;
        wolfsentry_route_get_metadata(rule_route, &metadata);

        fprintf(stderr, " insert_time \t\t");  PRINT_DATE(sentry,
                                                metadata.insert_time);
        fprintf(stderr, " last_hit_time \t\t"); PRINT_DATE(sentry,
                                               metadata.last_hit_time);
        fprintf(stderr, " last_penaltybox_time \t"); PRINT_DATE(sentry,
                                                metadata.last_penaltybox_time);
        fprintf(stderr, " connection_count \t%d\n", metadata.connection_count);
        fprintf(stderr, " derogatory_count \t%d\n", metadata.derogatory_count);
        fprintf(stderr, " commendable_count \t%d\n", metadata.commendable_count);
        fprintf(stderr, "\n");
    }
    
    return 0;
}
/**
 * Callback function for handle-update action
 *
 * @return 0 for successful, otherwise wolfsentry error code
 */
static wolfsentry_errcode_t test_update_action(
    struct wolfsentry_context *sentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event = 
                                    wolfsentry_route_parent_event(rule_route);
    const char *tag_success = "authentication_succeeded";

    (void)handler_arg;
    (void)route_table;
    (void)action_results;
    (void)target_route;
    (void)action_type;

    fprintf(stderr, "action callback: a=\"%s\" parent_event=\"%s\" "
                                "trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
            wolfsentry_action_get_label(action),
            wolfsentry_event_get_label(parent_event),
            wolfsentry_event_get_label(trigger_event),
            action_type,
            wolfsentry_get_object_id(rule_route),
            caller_arg);

    /* clear derogatory count */
    if (XSTRNCMP(wolfsentry_event_get_label(trigger_event), tag_success,
        XSTRLEN(tag_success)) ==0 && 
        ((struct wolfsentry_data *)caller_arg)->rule_route) {
            printf("clear derogatory count\n");
            /* clear derogatory count */
            wolfsentry_route_reset_derogatory_count(
                    sentry, 
                    ((struct wolfsentry_data *)caller_arg)->rule_route, NULL);
            /* release object reference */
             wolfsentry_route_drop_reference(sentry,
                    ((struct wolfsentry_data *)caller_arg)->rule_route, NULL);
            
            ((struct wolfsentry_data *)caller_arg)->rule_route = NULL;
    }
    
    if (rule_route) {

        fprintf(stderr, "Route detail: \n");
        wolfsentry_route_render(wolfsentry, rule_route, stdout);
        
        struct wolfsentry_route_metadata_exports metadata;
        wolfsentry_route_get_metadata(rule_route, &metadata);

        fprintf(stderr, " insert_time \t\t");  PRINT_DATE(sentry,
                                                metadata.insert_time);
        fprintf(stderr, " last_hit_time \t\t"); PRINT_DATE(sentry,
                                               metadata.last_hit_time);
        fprintf(stderr, " last_penaltybox_time \t"); PRINT_DATE(sentry,
                                                metadata.last_penaltybox_time);
        fprintf(stderr, " connection_count \t%d\n", metadata.connection_count);
        fprintf(stderr, " derogatory_count \t%d\n", metadata.derogatory_count);
        fprintf(stderr, " commendable_count \t%d\n", metadata.commendable_count);
        fprintf(stderr, "\n");
    }

    return 0;
}

/*
 * Callback that is fired when an action is taken excepts auth_success 
 * and auth_fail this can be used for debugging for now 
 */
static wolfsentry_errcode_t test_action(
    struct wolfsentry_context *sentry,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    const struct wolfsentry_event *parent_event =
                                    wolfsentry_route_parent_event(rule_route);

    (void)sentry;
    (void)handler_arg;
    (void)route_table;
    (void)action_results;
    (void)target_route;
    
    if (wolfsentry_hook_verbose) {
        fprintf(stderr, "action callback: a=\"%s\" parent_event=\"%s\" "
                                "trigger=\"%s\" t=%u r_id=%u caller_arg=%p\n",
            wolfsentry_action_get_label(action),
            wolfsentry_event_get_label(parent_event),
            wolfsentry_event_get_label(trigger_event),
            action_type,
            wolfsentry_get_object_id(rule_route),
            caller_arg);
        
        if (rule_route) {

            fprintf(stderr, "rule_route render: \n");
            wolfsentry_route_render(wolfsentry, rule_route, stdout);
            
            struct wolfsentry_route_metadata_exports metadata;
            
            wolfsentry_route_get_metadata(rule_route, &metadata);

            printf(" insert_time \t\t");  PRINT_DATE(sentry,
                                                metadata.insert_time);
            printf(" last_hit_time \t\t"); PRINT_DATE(sentry,
                                                metadata.last_hit_time);
            printf(" last_penaltybox_time \t"); PRINT_DATE(sentry,
                                                metadata.last_penaltybox_time);
            printf(" connection_count \t%d\n", metadata.connection_count);
            printf(" derogatory_count \t%d\n", metadata.derogatory_count);
            printf(" commendable_count \t%d\n", metadata.commendable_count);
            printf("\n");
        }
    }

    /* check out role_route so that application-level can manipulate a value  */
    if (rule_route && caller_arg != NULL &&
       !((struct wolfsentry_data *)caller_arg)->rule_route &&
        wolfsentry_object_checkout(rule_route) >= 0 ) {
        ((struct wolfsentry_data *)caller_arg)->rule_route = rule_route;
    }

    return 0;
}
/**
 *  Store end points to be used later
 * @param remote remote address information
 * @param local  local address information
 * @param proto  protocal information
 * @param flags  wolfsentry route flag
 * @param wolfsentry_data_out keep endpoints information to be used
 * @return 1 for successful, otherwise 0
 */
static WC_INLINE int wolfsentry_store_endpoints(
    SOCKADDR_IN_T *remote,
    SOCKADDR_IN_T *local,
    int proto,
    wolfsentry_route_flags_t flags,
    struct wolfsentry_data **wolfsentry_data_out)
{
    struct wolfsentry_data *wolfsentry_data = (struct wolfsentry_data *)WMALLOC(
        sizeof *wolfsentry_data, NULL, DYNAMIC_TYPE_SOCKADDR);
    if (wolfsentry_data == NULL)
        return 0;

    wolfsentry_data->heap = NULL;
    wolfsentry_data->alloctype = DYNAMIC_TYPE_SOCKADDR;
    wolfsentry_data->rule_route = NULL;

    if ((sizeof wolfsentry_data->remote.addr < sizeof remote->sin_addr) ||
        (sizeof wolfsentry_data->local.addr < sizeof local->sin_addr))
        return 0;
    wolfsentry_data->remote.sa_family =
                        wolfsentry_data->local.sa_family = remote->sin_family;
    wolfsentry_data->remote.sa_port = ntohs(remote->sin_port);
    wolfsentry_data->local.sa_port = ntohs(local->sin_port);
    if (WOLFSENTRY_MASKIN_BITS(flags,
                            WOLFSENTRY_ROUTE_FLAG_SA_REMOTE_ADDR_WILDCARD)) {
        wolfsentry_data->remote.addr_len = 0;
        XMEMSET(wolfsentry_data->remote.addr, 0, sizeof remote->sin_addr);
    } else {
        wolfsentry_data->remote.addr_len =
                                        sizeof remote->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->remote.addr,
                                    &remote->sin_addr, sizeof remote->sin_addr);
    }
    if (WOLFSENTRY_MASKIN_BITS(flags,
                                WOLFSENTRY_ROUTE_FLAG_SA_LOCAL_ADDR_WILDCARD)) {
        wolfsentry_data->local.addr_len = 0;
        XMEMSET(wolfsentry_data->local.addr, 0, sizeof local->sin_addr);
    } else {
        wolfsentry_data->local.addr_len =
                                        sizeof local->sin_addr * BITS_PER_BYTE;
        XMEMCPY(wolfsentry_data->local.addr,
                                    &local->sin_addr, sizeof local->sin_addr);
    }

    wolfsentry_data->remote.sa_proto = wolfsentry_data->local.sa_proto = proto;
    wolfsentry_data->remote.interface = wolfsentry_data->local.interface = 0;
    wolfsentry_data->flags = flags;

    if (wolfsentry_data_out != NULL)
        *wolfsentry_data_out = wolfsentry_data;

    return 1;
}
/**
 *  Set up wolfsentry 
 * @param _wolfsentry  wolfsentry context object
 * @param s  _wolfsentry_config_path path for JSON configuration file
 *
 * @return 0 for successful, otherwise wolfsentry error code
 */
static int wolfsentry_setup(
    struct wolfsentry_context **_wolfsentry,
    const char *_wolfsentry_config_path)
{
    wolfsentry_errcode_t ret;
    wolfsentry_ent_id_t id;
    
    ret =  wolfsentry_init(NULL /* hpi */, NULL /* default config */,
                           _wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init() returned " WOLFSENTRY_ERROR_FMT "\n",
                WOLFSENTRY_ERROR_FMT_ARGS(ret));
        err_sys("unable to initialize wolfSentry");
    }


    /* Insert the possible actions into wolfSentry */
    wolfsentry_action_insert(      wolfsentry,
                                   "handle-insert",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-delete",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-update",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_update_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-match",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "notify-on-decision",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "notify-on-match",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "handle-connect",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

   wolfsentry_action_insert(
                                   wolfsentry,
                                   "auth-succeeded",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   auth_succeed_action,
                                   NULL,
                                   &id);
                                   
   wolfsentry_action_insert(
                                   wolfsentry,
                                   "auth-failed",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   auth_failed_action,
                                   NULL,
                                   &id);

    wolfsentry_action_insert(
                                   wolfsentry,
                                   "auth-failed",
                                   WOLFSENTRY_LENGTH_NULL_TERMINATED,
                                   WOLFSENTRY_ACTION_FLAG_NONE,
                                   test_action,
                                   NULL,
                                   &id);

#if !defined(NO_FILESYSTEM) && !defined(WOLFSENTRY_NO_JSON)
    if (_wolfsentry_config_path != NULL) {
        char buf[512], err_buf[512];
        struct wolfsentry_json_process_state *jps;

        FILE *f = fopen(_wolfsentry_config_path, "r");

        if (f == NULL) {
            fprintf(stderr, "fopen(%s): %s\n",_wolfsentry_config_path,
                                                            strerror(errno));
            err_sys("unable to open wolfSentry config file");
        }

        if ((ret = wolfsentry_config_json_init(
                 *_wolfsentry,
                 WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
                 &jps)) < 0) {
            fprintf(stderr, "wolfsentry_config_json_init() returned "
                    WOLFSENTRY_ERROR_FMT "\n",
                    WOLFSENTRY_ERROR_FMT_ARGS(ret));
            err_sys("error while initializing wolfSentry config parser");
        }

        for (;;) {
            size_t n = fread(buf, 1, sizeof buf, f);
            if ((n < sizeof buf) && ferror(f)) {
                fprintf(stderr,"fread(%s): %s\n",_wolfsentry_config_path, 
                                                            strerror(errno));
                err_sys("error while reading wolfSentry config file");
            }

            ret = wolfsentry_config_json_feed(jps, buf, n, err_buf, 
                                                                sizeof err_buf);
            if (ret < 0) {
                fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
                err_sys("error while loading wolfSentry config file");
            }
            if ((n < sizeof buf) && feof(f))
                break;
        }
        fclose(f);

        if ((ret = wolfsentry_config_json_fini(&jps, err_buf, 
                                                        sizeof err_buf)) < 0) {
            fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            err_sys("error while loading wolfSentry config file");
        }

    }
#endif /* !NO_FILESYSTEM && !WOLFSENTRY_NO_JSON */

    return 0;
}
#endif /* _WOLFSENTRY_TEST_H_ */
