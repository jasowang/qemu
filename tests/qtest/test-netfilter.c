/*
 * QTest testcase for netfilter
 *
 * Copyright (c) 2015 FUJITSU LIMITED
 * Author: Yang Hongyang <yanghy@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "libqtest-single.h"
#include "qobject/qdict.h"

/* add a netfilter to a netdev and then remove it */
static void add_one_netfilter(void)
{
    QDict *response;

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f0',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'object-del',"
                   " 'arguments': {"
                   "   'id': 'qtest-f0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);
}

/* add a netfilter to a netdev and then remove the netdev */
static void remove_netdev_with_one_netfilter(void)
{
    QDict *response;

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f0',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'netdev_del',"
                   " 'arguments': {"
                   "   'id': 'qtest-bn0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    /* add back the netdev */
    response = qmp("{'execute': 'netdev_add',"
                   " 'arguments': {"
                   "   'type': 'user',"
                   "   'id': 'qtest-bn0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);
}

/* add multi(2) netfilters to a netdev and then remove them */
static void add_multi_netfilter(void)
{
    QDict *response;

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f0',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f1',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'object-del',"
                   " 'arguments': {"
                   "   'id': 'qtest-f0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'object-del',"
                   " 'arguments': {"
                   "   'id': 'qtest-f1'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);
}

/*
 * Test query-netfilter-stats for TX direction using filter-mirror.
 *
 * Traffic flow:
 *   test_sock -> socket backend (bn0) -> filter-mirror (TX stats++) -> chardev
 */
static void test_query_netfilter_stats_tx(void)
{
    QTestState *qts;
    QDict *response;
    QList *stats_list;
    const QListEntry *entry;
    int send_sock[2], recv_sock[2];
    int ret;
    char send_buf[] = "Hello TX stats!";
    uint32_t size = sizeof(send_buf);
    uint32_t net_size;
    bool found_filter = false;

    net_size = htonl(size);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, send_sock);
    g_assert_cmpint(ret, !=, -1);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, recv_sock);
    g_assert_cmpint(ret, !=, -1);

    qts = qtest_initf(
        "-nic socket,id=bn0,fd=%d "
        "-chardev socket,id=mirror0,fd=%d "
        "-object filter-mirror,id=f0,netdev=bn0,queue=tx,outdev=mirror0",
        send_sock[1], recv_sock[1]);

    qtest_qmp_assert_success(qts, "{ 'execute' : 'query-status'}");

    /* Query initial stats */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    stats_list = qdict_get_qlist(response, "return");
    g_assert(stats_list);

    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "f0") == 0) {
            found_filter = true;
            g_assert_cmpint(qdict_get_int(stats, "packets-tx"), ==, 0);
            g_assert_cmpint(qdict_get_int(stats, "bytes-tx"), ==, 0);
            g_assert_cmpstr(qdict_get_str(stats, "type"), ==, "filter-mirror");
        }
    }
    g_assert(found_filter);
    qobject_unref(response);

    /* Send packet - triggers TX direction */
    struct iovec iov[] = {
        { .iov_base = &net_size, .iov_len = sizeof(net_size) },
        { .iov_base = send_buf, .iov_len = sizeof(send_buf) },
    };
    ret = iov_send(send_sock[0], iov, 2, 0, sizeof(net_size) + sizeof(send_buf));
    g_assert_cmpint(ret, ==, sizeof(send_buf) + sizeof(net_size));

    g_usleep(100000);

    /* Verify TX stats updated */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    stats_list = qdict_get_qlist(response, "return");

    found_filter = false;
    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "f0") == 0) {
            found_filter = true;
            g_assert_cmpint(qdict_get_int(stats, "packets-tx"), >=, 1);
            g_assert_cmpint(qdict_get_int(stats, "bytes-tx"), >=, sizeof(send_buf));
        }
    }
    g_assert(found_filter);
    qobject_unref(response);

    close(send_sock[0]);
    close(send_sock[1]);
    close(recv_sock[0]);
    close(recv_sock[1]);
    qtest_quit(qts);
}

/*
 * Test query-netfilter-stats for RX direction using filter-redirector.
 *
 * Traffic flow:
 *   indev_sock -> chardev (indev) -> filter-redirector -> netdev (RX path)
 *
 * When filter-redirector reads from indev and calls redirector_to_filter(),
 * it passes the packet to the next filter in the chain via
 * qemu_netfilter_pass_to_next(). We add a second filter (filter-buffer)
 * that will receive the packet and update its RX stats.
 */
static void test_query_netfilter_stats_rx(void)
{
    QTestState *qts;
    QDict *response;
    QList *stats_list;
    const QListEntry *entry;
    int backend_sock[2], indev_sock[2];
    int ret;
    char send_buf[] = "Hello RX stats!";
    uint32_t size = sizeof(send_buf);
    uint32_t net_size;
    bool found_buffer = false;

    net_size = htonl(size);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, backend_sock);
    g_assert_cmpint(ret, !=, -1);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, indev_sock);
    g_assert_cmpint(ret, !=, -1);

    /*
     * Setup:
     * - filter-redirector (rd0, queue=rx, indev) at tail - injects data
     * - filter-buffer (fb0, queue=rx) at head - receives and counts
     *
     * RX direction traverses from tail to head, so:
     * indev -> rd0 (reads, calls pass_to_next) -> fb0 (receive_iov, RX stats++)
     */
    qts = qtest_initf(
        "-nic socket,id=bn0,fd=%d "
        "-chardev socket,id=indev0,fd=%d "
        "-object filter-buffer,id=fb0,netdev=bn0,queue=rx,interval=1000000,position=head "
        "-object filter-redirector,id=rd0,netdev=bn0,queue=rx,indev=indev0,position=tail",
        backend_sock[1], indev_sock[1]);

    qtest_qmp_assert_success(qts, "{ 'execute' : 'query-status'}");

    /* Query initial stats - fb0 should have zero RX */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    stats_list = qdict_get_qlist(response, "return");
    g_assert(stats_list);

    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "fb0") == 0) {
            found_buffer = true;
            g_assert_cmpint(qdict_get_int(stats, "packets-rx"), ==, 0);
            g_assert_cmpint(qdict_get_int(stats, "bytes-rx"), ==, 0);
            g_assert_cmpstr(qdict_get_str(stats, "type"), ==, "filter-buffer");
        }
    }
    g_assert(found_buffer);
    qobject_unref(response);

    /* Inject packet via indev - triggers RX direction */
    struct iovec iov[] = {
        { .iov_base = &net_size, .iov_len = sizeof(net_size) },
        { .iov_base = send_buf, .iov_len = sizeof(send_buf) },
    };
    ret = iov_send(indev_sock[0], iov, 2, 0, sizeof(net_size) + sizeof(send_buf));
    g_assert_cmpint(ret, ==, sizeof(send_buf) + sizeof(net_size));

    g_usleep(100000);

    /* Verify fb0's RX stats and rd0's indev stats updated */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    stats_list = qdict_get_qlist(response, "return");

    found_buffer = false;
    bool found_redirector = false;
    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "fb0") == 0) {
            found_buffer = true;
            g_assert_cmpint(qdict_get_int(stats, "packets-rx"), >=, 1);
            g_assert_cmpint(qdict_get_int(stats, "bytes-rx"), >=, sizeof(send_buf));
        }
        if (g_strcmp0(name, "rd0") == 0) {
            QList *counters;
            const QListEntry *centry;
            bool found_indev = false;

            found_redirector = true;
            /* Verify indev counter in counters array */
            g_assert(qdict_haskey(stats, "counters"));
            counters = qdict_get_qlist(stats, "counters");
            for (centry = qlist_first(counters); centry;
                 centry = qlist_next(centry)) {
                QDict *counter = qobject_to(QDict, qlist_entry_obj(centry));
                const char *cname = qdict_get_str(counter, "name");
                if (g_strcmp0(cname, "indev") == 0) {
                    found_indev = true;
                    g_assert_cmpint(qdict_get_int(counter, "packets"), >=, 1);
                    g_assert_cmpint(qdict_get_int(counter, "bytes"),
                                    >=, sizeof(send_buf));
                }
            }
            g_assert(found_indev);
        }
    }
    g_assert(found_buffer);
    g_assert(found_redirector);
    qobject_unref(response);

    /* Test query by name */
    response = qtest_qmp(qts,
                         "{'execute': 'query-netfilter-stats',"
                         " 'arguments': { 'name': 'fb0' }}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    stats_list = qdict_get_qlist(response, "return");
    g_assert_cmpint(qlist_size(stats_list), ==, 1);
    qobject_unref(response);

    /* Test error for non-existent filter */
    response = qtest_qmp(qts,
                         "{'execute': 'query-netfilter-stats',"
                         " 'arguments': { 'name': 'nonexistent' }}");
    g_assert(response);
    g_assert(qdict_haskey(response, "error"));
    qobject_unref(response);

    close(backend_sock[0]);
    close(backend_sock[1]);
    close(indev_sock[0]);
    close(indev_sock[1]);
    qtest_quit(qts);
}

/*
 * Test filter-redirector outdev statistics.
 *
 * Traffic flow:
 *   test_sock -> socket backend -> filter-redirector (outdev) -> chardev
 *
 * When data passes through filter-redirector with outdev configured,
 * it sends the data to outdev and updates outdev statistics.
 */
static void test_query_netfilter_stats_redirector_outdev(void)
{
    QTestState *qts;
    QDict *response;
    QList *stats_list;
    const QListEntry *entry;
    int send_sock[2], recv_sock[2];
    int ret;
    char send_buf[] = "Hello outdev stats!";
    uint32_t size = sizeof(send_buf);
    uint32_t net_size;
    bool found_redirector = false;

    net_size = htonl(size);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, send_sock);
    g_assert_cmpint(ret, !=, -1);

    ret = socketpair(PF_UNIX, SOCK_STREAM, 0, recv_sock);
    g_assert_cmpint(ret, !=, -1);

    qts = qtest_initf(
        "-nic socket,id=bn0,fd=%d "
        "-chardev socket,id=outdev0,fd=%d "
        "-object filter-redirector,id=rd0,netdev=bn0,queue=tx,outdev=outdev0",
        send_sock[1], recv_sock[1]);

    qtest_qmp_assert_success(qts, "{ 'execute' : 'query-status'}");

    /* Query initial stats */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    stats_list = qdict_get_qlist(response, "return");

    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "rd0") == 0) {
            QList *counters;
            const QListEntry *centry;
            bool found_outdev = false;

            found_redirector = true;
            g_assert(qdict_haskey(stats, "counters"));
            counters = qdict_get_qlist(stats, "counters");
            for (centry = qlist_first(counters); centry;
                 centry = qlist_next(centry)) {
                QDict *counter = qobject_to(QDict, qlist_entry_obj(centry));
                const char *cname = qdict_get_str(counter, "name");
                if (g_strcmp0(cname, "outdev") == 0) {
                    found_outdev = true;
                    g_assert_cmpint(qdict_get_int(counter, "packets"), ==, 0);
                    g_assert_cmpint(qdict_get_int(counter, "bytes"), ==, 0);
                }
            }
            g_assert(found_outdev);
        }
    }
    g_assert(found_redirector);
    qobject_unref(response);

    /* Send packet - triggers TX direction and outdev */
    struct iovec iov[] = {
        { .iov_base = &net_size, .iov_len = sizeof(net_size) },
        { .iov_base = send_buf, .iov_len = sizeof(send_buf) },
    };
    ret = iov_send(send_sock[0], iov, 2, 0, sizeof(net_size) + sizeof(send_buf));
    g_assert_cmpint(ret, ==, sizeof(send_buf) + sizeof(net_size));

    g_usleep(100000);

    /* Verify outdev stats updated */
    response = qtest_qmp(qts, "{'execute': 'query-netfilter-stats'}");
    g_assert(response);
    stats_list = qdict_get_qlist(response, "return");

    found_redirector = false;
    for (entry = qlist_first(stats_list); entry; entry = qlist_next(entry)) {
        QDict *stats = qobject_to(QDict, qlist_entry_obj(entry));
        const char *name = qdict_get_str(stats, "name");
        if (g_strcmp0(name, "rd0") == 0) {
            QList *counters;
            const QListEntry *centry;
            bool found_outdev = false;

            found_redirector = true;
            /* TX stats should also be updated */
            g_assert_cmpint(qdict_get_int(stats, "packets-tx"), >=, 1);

            /* Verify outdev counter */
            counters = qdict_get_qlist(stats, "counters");
            for (centry = qlist_first(counters); centry;
                 centry = qlist_next(centry)) {
                QDict *counter = qobject_to(QDict, qlist_entry_obj(centry));
                const char *cname = qdict_get_str(counter, "name");
                if (g_strcmp0(cname, "outdev") == 0) {
                    found_outdev = true;
                    g_assert_cmpint(qdict_get_int(counter, "packets"), >=, 1);
                    g_assert_cmpint(qdict_get_int(counter, "bytes"),
                                    >=, sizeof(send_buf));
                }
            }
            g_assert(found_outdev);
        }
    }
    g_assert(found_redirector);
    qobject_unref(response);

    close(send_sock[0]);
    close(send_sock[1]);
    close(recv_sock[0]);
    close(recv_sock[1]);
    qtest_quit(qts);
}

/* add multi(2) netfilters to a netdev and then remove the netdev */
static void remove_netdev_with_multi_netfilter(void)
{
    QDict *response;

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f0',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'object-add',"
                   " 'arguments': {"
                   "   'qom-type': 'filter-buffer',"
                   "   'id': 'qtest-f1',"
                   "   'netdev': 'qtest-bn0',"
                   "   'queue': 'rx',"
                   "   'interval': 1000"
                   "}}");

    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    response = qmp("{'execute': 'netdev_del',"
                   " 'arguments': {"
                   "   'id': 'qtest-bn0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);

    /* add back the netdev */
    response = qmp("{'execute': 'netdev_add',"
                   " 'arguments': {"
                   "   'type': 'user',"
                   "   'id': 'qtest-bn0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    qobject_unref(response);
}

int main(int argc, char **argv)
{
    int ret;
    char *args;

    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/netfilter/addremove_one", add_one_netfilter);
    qtest_add_func("/netfilter/remove_netdev_one",
                   remove_netdev_with_one_netfilter);
    qtest_add_func("/netfilter/addremove_multi", add_multi_netfilter);
    qtest_add_func("/netfilter/remove_netdev_multi",
                   remove_netdev_with_multi_netfilter);

    qtest_add_func("/netfilter/query_stats_tx", test_query_netfilter_stats_tx);
    qtest_add_func("/netfilter/query_stats_rx", test_query_netfilter_stats_rx);
    qtest_add_func("/netfilter/query_stats_redirector_outdev",
                   test_query_netfilter_stats_redirector_outdev);

    args = g_strdup_printf("-nic user,id=qtest-bn0");
    qtest_start(args);
    ret = g_test_run();

    qtest_end();
    g_free(args);

    return ret;
}
