/*
 * xgw_agent.c
 * X-Gateway Wi-Fi Gateway(AP) 보안로그 전송 Agent
 *
 * 기준 문서 : X-Gateway 보안로그 / Wi-Fi 정책 연동 정의서 H1Radio v0.1 (미완성본)
 *
 * 동작
 *   1) AF_PACKET 소켓으로 지정 인터페이스(br-lan 등)의 패킷을 캡처
 *   2) config의 filter 조건에 맞는 패킷만 PACKET 메시지(JSON)로 생성
 *   3) 메모리 큐에 적재 후 TCP 지속연결로 수집 Agent(기본 183.99.77.198:50010)에 전송
 *   4) ACK 수신 시 큐에서 삭제 / ACK 미수신·REJECTED(retryable) 시 동일 message_id로 재전송
 *   5) 연결 단절 시 지수 백오프로 자동 재연결, 미확인(in-flight) 메시지는 재연결 후 재전송
 *
 * Build : gcc -O2 -Wall -Wextra -o xgw_agent xgw_agent.c
 * Run   : ./xgw_agent -c /etc/xgw/xgw_agent.conf          (daemon = 1 이면 백그라운드)
 *         ./xgw_agent -f -c ./xgw_agent.conf              (-f: 포그라운드 강제, 로그 stderr)
 * 권한  : AF_PACKET 사용을 위해 root(CAP_NET_RAW) 필요
 * 신호  : SIGTERM/SIGINT 종료, SIGHUP 로그 파일 재오픈(logrotate 용)
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define MAX_PORTS   16
#define MAX_WINDOW  256
#define RX_SZ       65536
#define PKT_SZ      (65536 + 64)
#define STR_SZ      128

enum framing { FRAMING_NEWLINE = 0, FRAMING_NONE, FRAMING_LENGTH };
enum conn_state { ST_DISC = 0, ST_CONNECTING, ST_CONNECTED };

struct filter {
    int all, arp, eapol, dhcp, dns, icmp, icmp6;
    uint16_t tcp[MAX_PORTS]; int ntcp;
    uint16_t udp[MAX_PORTS]; int nudp;
};

struct cfg {
    /* 연동 */
    char server_ip[64];
    int  server_port;
    int  connect_timeout_ms;
    int  reconnect_min_ms, reconnect_max_ms;
    int  ack_timeout_ms, max_retry, wait_ack, window;
    enum framing framing;
    int  ka_idle, ka_intvl, ka_cnt;
    /* 메시지 */
    char schema_version[16];
    char ap_id[STR_SZ];          /* "auto" 이면 ap_id_iface 의 MAC 사용 */
    char ap_id_iface[IFNAMSIZ];
    /* 캡처 */
    char iface[IFNAMSIZ];
    int  snaplen, promisc, include_outgoing;
    char station_id_mode[8];     /* src | dst */
    struct filter flt;
    int  max_pps;                /* 0 = 무제한 */
    /* 큐/운영 */
    int  queue_max;
    int  stats_interval_sec;
    int  daemonize;
    char pidfile[256];
    char log_file[256];          /* 비우면 daemon: syslog, foreground: stderr */
    int  log_level;              /* 0 ERR, 1 INFO, 2 DEBUG */
};

struct msg {
    char   id[40];
    char  *json;
    size_t jlen;
    int    tx_cnt;
    int    need_tx;
    int64_t deadline_ms;
};

struct stats {
    uint64_t captured, filtered, own_skipped, dropped_rate, dropped_queue, dropped_reject;
    uint64_t queued, sent, acked, dup, rejected, retrans, connects, disconnects;
};

/* ---------------------------------------------------------------- 전역 */
static struct cfg   g;
static struct stats S;
static volatile sig_atomic_t g_stop = 0, g_hup = 0;
static int    g_daemon = 0;
static FILE  *g_logfp = NULL;
static int    g_urandom = -1;
static int    g_capfd = -1, g_pidfd = -1;
static char   g_ap_esc[STR_SZ * 2], g_if_esc[IFNAMSIZ * 2];
static struct sockaddr_in g_srv;

/* 큐 */
static struct msg **q; static size_t qhead, qcount, qcap;
static struct msg *infl[MAX_WINDOW]; static int ninfl;

/* 연결 */
static enum conn_state cst = ST_DISC;
static int     sfd = -1;
static int64_t next_conn_ms, conn_deadline_ms;
static int     backoff_ms;
static uint8_t *txb; static size_t txlen, txoff, txcap;
static uint8_t rxb[RX_SZ]; static size_t rxlen;
static char    tmpj[RX_SZ + 1];
static uint8_t pkt[PKT_SZ];

/* ---------------------------------------------------------------- 시간/로그 */
static int64_t mono_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void now_rfc3339(char *out, size_t sz)
{
    struct timespec ts; struct tm tm; char base[32];
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, sz, "%s.%03dZ", base, (int)(ts.tv_nsec / 1000000L) % 1000);
}

static void logmsg(int lvl, const char *fmt, ...)
{
    if (lvl > g.log_level) return;
    char body[512];
    va_list ap; va_start(ap, fmt); vsnprintf(body, sizeof(body), fmt, ap); va_end(ap);
    static const char *tag[] = { "ERR", "INF", "DBG" };
    if (g_logfp) {
        char ts[40]; now_rfc3339(ts, sizeof(ts));
        fprintf(g_logfp, "%s [%s] %s\n", ts, tag[lvl], body); fflush(g_logfp);
    } else if (g_daemon) {
        syslog(lvl == 0 ? LOG_ERR : lvl == 1 ? LOG_INFO : LOG_DEBUG, "%s", body);
    } else {
        fprintf(stderr, "[%s] %s\n", tag[lvl], body);
    }
}
#define LOGE(...) logmsg(0, __VA_ARGS__)
#define LOGI(...) logmsg(1, __VA_ARGS__)
#define LOGD(...) logmsg(2, __VA_ARGS__)

static void log_open(void)
{
    if (g_logfp) { fclose(g_logfp); g_logfp = NULL; }
    if (g.log_file[0]) {
        g_logfp = fopen(g.log_file, "a");
        if (!g_logfp) fprintf(stderr, "log_file open 실패: %s\n", g.log_file);
    }
}

/* ---------------------------------------------------------------- 유틸 */
static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static void gen_uuid(char *out, size_t sz)
{
    unsigned char b[16];
    if (g_urandom < 0 || read(g_urandom, b, 16) != 16)
        for (int i = 0; i < 16; i++) b[i] = (unsigned char)(rand() & 0xFF);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, sz, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static void json_escape(const char *in, char *out, size_t sz)
{
    size_t o = 0;
    for (; *in && o + 7 < sz; in++) {
        unsigned char c = (unsigned char)*in;
        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20) o += (size_t)snprintf(out + o, sz - o, "\\u%04x", c);
            else out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static void mac_str(const uint8_t *m, char *out)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ---------------------------------------------------------------- Config */
static void parse_filter(char *v, struct filter *f)
{
    memset(f, 0, sizeof(*f));
    char *sp = NULL;
    for (char *t = strtok_r(v, ",", &sp); t; t = strtok_r(NULL, ",", &sp)) {
        t = trim(t);
        if      (!strcasecmp(t, "all"))   f->all = 1;
        else if (!strcasecmp(t, "arp"))   f->arp = 1;
        else if (!strcasecmp(t, "eapol")) f->eapol = 1;
        else if (!strcasecmp(t, "dhcp"))  f->dhcp = 1;
        else if (!strcasecmp(t, "dns"))   f->dns = 1;
        else if (!strcasecmp(t, "icmp"))  f->icmp = 1;
        else if (!strcasecmp(t, "icmp6")) f->icmp6 = 1;
        else if (!strncasecmp(t, "tcp_port:", 9) && f->ntcp < MAX_PORTS) f->tcp[f->ntcp++] = (uint16_t)atoi(t + 9);
        else if (!strncasecmp(t, "udp_port:", 9) && f->nudp < MAX_PORTS) f->udp[f->nudp++] = (uint16_t)atoi(t + 9);
        else fprintf(stderr, "[WARN] 알 수 없는 filter 항목: %s\n", t);
    }
}

static void cfg_defaults(void)
{
    memset(&g, 0, sizeof(g));
    snprintf(g.server_ip, sizeof(g.server_ip), "183.99.77.198");
    g.server_port = 50010;
    g.connect_timeout_ms = 5000;
    g.reconnect_min_ms = 1000;  g.reconnect_max_ms = 30000;
    g.ack_timeout_ms = 3000;    g.max_retry = 3;  g.wait_ack = 1;  g.window = 32;
    g.framing = FRAMING_NEWLINE;
    g.ka_idle = 30; g.ka_intvl = 10; g.ka_cnt = 3;
    snprintf(g.schema_version, sizeof(g.schema_version), "1.0");
    snprintf(g.ap_id, sizeof(g.ap_id), "auto");
    snprintf(g.ap_id_iface, sizeof(g.ap_id_iface), "br-lan");
    snprintf(g.iface, sizeof(g.iface), "br-lan");
    g.snaplen = 256; g.promisc = 0; g.include_outgoing = 0;
    snprintf(g.station_id_mode, sizeof(g.station_id_mode), "src");
    g.flt.arp = 1;
    g.queue_max = 2000;
    g.stats_interval_sec = 60;
    g.log_level = 1;
}

static int cfg_load(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "[ERR] config open 실패: %s (%s)\n", path, strerror(errno)); return -1; }
    char line[1024]; int ln = 0;
    while (fgets(line, sizeof(line), fp)) {
        ln++;
        char *p = trim(line);
        if (!*p || *p == '#' || *p == ';') continue;
        char *eq = strchr(p, '=');
        if (!eq) { fprintf(stderr, "[WARN] config:%d '=' 없음\n", ln); continue; }
        *eq = '\0';
        char *k = trim(p), *v = trim(eq + 1);
        char *hash = strstr(v, " #"); if (hash) { *hash = '\0'; v = trim(v); }

#define KI(n, f) else if (!strcmp(k, n)) g.f = atoi(v)
#define KS(n, f) else if (!strcmp(k, n)) snprintf(g.f, sizeof(g.f), "%s", v)
        if (0) {}
        KS("server_ip", server_ip); KI("server_port", server_port);
        KI("connect_timeout_ms", connect_timeout_ms);
        KI("reconnect_min_ms", reconnect_min_ms); KI("reconnect_max_ms", reconnect_max_ms);
        KI("ack_timeout_ms", ack_timeout_ms); KI("max_retry", max_retry);
        KI("wait_ack", wait_ack); KI("window", window);
        KI("keepalive_idle", ka_idle); KI("keepalive_intvl", ka_intvl); KI("keepalive_cnt", ka_cnt);
        KS("schema_version", schema_version); KS("ap_id", ap_id); KS("ap_id_iface", ap_id_iface);
        KS("interface", iface); KI("snaplen", snaplen); KI("promisc", promisc);
        KI("include_outgoing", include_outgoing); KS("station_id_mode", station_id_mode);
        KI("max_pps", max_pps); KI("queue_max", queue_max);
        KI("stats_interval_sec", stats_interval_sec);
        KI("daemon", daemonize); KS("pidfile", pidfile); KS("log_file", log_file);
        KI("log_level", log_level);
        else if (!strcmp(k, "framing")) {
            if      (!strcasecmp(v, "newline")) g.framing = FRAMING_NEWLINE;
            else if (!strcasecmp(v, "none"))    g.framing = FRAMING_NONE;
            else if (!strcasecmp(v, "length"))  g.framing = FRAMING_LENGTH;
            else fprintf(stderr, "[WARN] config:%d 알 수 없는 framing '%s'\n", ln, v);
        }
        else if (!strcmp(k, "filter")) parse_filter(v, &g.flt);
        else fprintf(stderr, "[WARN] config:%d 알 수 없는 키 '%s'\n", ln, k);
    }
    fclose(fp);

    if (g.server_port <= 0 || g.server_port > 65535) { fprintf(stderr, "[ERR] server_port 오류\n"); return -1; }
    if (inet_pton(AF_INET, g.server_ip, &g_srv.sin_addr) != 1) { fprintf(stderr, "[ERR] server_ip 오류\n"); return -1; }
    g_srv.sin_family = AF_INET; g_srv.sin_port = htons((uint16_t)g.server_port);
    if (g.snaplen < 64) g.snaplen = 64;
    if (g.snaplen > 65535) g.snaplen = 65535;
    if (g.window < 1) g.window = 1;
    if (g.window > MAX_WINDOW) g.window = MAX_WINDOW;
    if (g.queue_max < 16) g.queue_max = 16;
    if (g.reconnect_min_ms < 100) g.reconnect_min_ms = 100;
    if (g.reconnect_max_ms < g.reconnect_min_ms) g.reconnect_max_ms = g.reconnect_min_ms;
    if (strcasecmp(g.station_id_mode, "src") && strcasecmp(g.station_id_mode, "dst")) {
        fprintf(stderr, "[ERR] station_id_mode 는 src|dst\n"); return -1;
    }
    return 0;
}

/* ap_id = auto → /sys/class/net/<if>/address (대문자) */
static int resolve_ap_id(void)
{
    if (strcasecmp(g.ap_id, "auto")) return 0;
    char path[128], buf[64] = "";
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", g.ap_id_iface);
    FILE *f = fopen(path, "r");
    if (!f || !fgets(buf, sizeof(buf), f)) {
        if (f) fclose(f);
        fprintf(stderr, "[ERR] ap_id=auto 인데 %s 를 읽을 수 없음\n", path);
        return -1;
    }
    fclose(f);
    char *b = trim(buf);
    for (char *c = b; *c; c++) *c = (char)toupper((unsigned char)*c);
    snprintf(g.ap_id, sizeof(g.ap_id), "%s", b);
    return 0;
}

/* ---------------------------------------------------------------- 큐 */
static void msg_free(struct msg *m) { if (m) { free(m->json); free(m); } }

static void q_pop_front_drop(void)
{
    msg_free(q[qhead]); qhead = (qhead + 1) % qcap; qcount--;
}
static void q_push_back(struct msg *m)
{
    if (qcount == qcap) { q_pop_front_drop(); S.dropped_queue++; }   /* 가장 오래된 것 폐기 */
    q[(qhead + qcount) % qcap] = m; qcount++;
}
static void q_push_front(struct msg *m)
{
    if (qcount == qcap) {                                             /* 가장 최신 것 폐기 */
        size_t t = (qhead + qcount - 1) % qcap;
        msg_free(q[t]); qcount--; S.dropped_queue++;
    }
    qhead = (qhead + qcap - 1) % qcap; q[qhead] = m; qcount++;
}

/* ---------------------------------------------------------------- 캡처 필터 */
static int in_ports(const uint16_t *l, int n, uint16_t p)
{
    for (int i = 0; i < n; i++) if (l[i] == p) return 1;
    return 0;
}

/* Ethernet(+VLAN 1중) 파싱. L3 오프셋/ethertype 반환, 실패 시 0 */
static size_t l3_off(const uint8_t *p, size_t len, uint16_t *et)
{
    if (len < 14) return 0;
    uint16_t t; memcpy(&t, p + 12, 2); t = ntohs(t);
    size_t off = 14;
    if (t == 0x8100 || t == 0x88A8) {
        if (len < 18) return 0;
        memcpy(&t, p + 16, 2); t = ntohs(t); off = 18;
    }
    *et = t; return off;
}

static int l4_match(uint8_t proto, const uint8_t *p, size_t len, size_t l4, int v6)
{
    const struct filter *f = &g.flt;
    if (proto == 1  && !v6) return f->icmp;
    if (proto == 58 &&  v6) return f->icmp6;
    if ((proto == 17 || proto == 6) && len >= l4 + 4) {
        uint16_t sp, dp; memcpy(&sp, p + l4, 2); memcpy(&dp, p + l4 + 2, 2);
        sp = ntohs(sp); dp = ntohs(dp);
        if (f->dns && (sp == 53 || dp == 53)) return 1;
        if (proto == 17) {
            if (f->dhcp && (((sp == 67 || sp == 68) && (dp == 67 || dp == 68)) ||
                            ((sp == 546 || sp == 547) && (dp == 546 || dp == 547)))) return 1;
            if (in_ports(f->udp, f->nudp, sp) || in_ports(f->udp, f->nudp, dp)) return 1;
        } else {
            if (in_ports(f->tcp, f->ntcp, sp) || in_ports(f->tcp, f->ntcp, dp)) return 1;
        }
    }
    return 0;
}

static int filter_match(const uint8_t *p, size_t len)
{
    if (g.flt.all) return 1;
    uint16_t et; size_t off = l3_off(p, len, &et);
    if (!off) return 0;
    if (et == 0x0806) return g.flt.arp;
    if (et == 0x888E) return g.flt.eapol;
    if (et == 0x0800) {
        if (len < off + 20) return 0;
        size_t ihl = (size_t)(p[off] & 0x0F) * 4;
        if (ihl < 20) return 0;
        return l4_match(p[off + 9], p, len, off + ihl, 0);
    }
    if (et == 0x86DD) {
        if (len < off + 40) return 0;
        return l4_match(p[off + 6], p, len, off + 40, 1);   /* 확장헤더 미해석 */
    }
    return 0;
}

/* Agent 자신의 로그 전송 트래픽(→ 서버) 캡처 방지: 피드백 루프 차단 */
static int is_own_traffic(const uint8_t *p, size_t len)
{
    uint16_t et; size_t off = l3_off(p, len, &et);
    if (!off || et != 0x0800 || len < off + 20) return 0;
    size_t ihl = (size_t)(p[off] & 0x0F) * 4;
    if (ihl < 20 || p[off + 9] != 6 || len < off + ihl + 4) return 0;
    uint32_t sip, dip; uint16_t sp, dp;
    memcpy(&sip, p + off + 12, 4); memcpy(&dip, p + off + 16, 4);
    memcpy(&sp, p + off + ihl, 2); memcpy(&dp, p + off + ihl + 2, 2);
    if (sip == g_srv.sin_addr.s_addr && sp == g_srv.sin_port) return 1;
    if (dip == g_srv.sin_addr.s_addr && dp == g_srv.sin_port) return 1;
    return 0;
}

/* ---------------------------------------------------------------- 캡처 */
static int capture_open(void)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) { fprintf(stderr, "[ERR] AF_PACKET socket 실패: %s (root 필요)\n", strerror(errno)); return -1; }
    unsigned idx = if_nametoindex(g.iface);
    if (!idx) { fprintf(stderr, "[ERR] 인터페이스 없음: %s\n", g.iface); close(fd); return -1; }
    struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET; sll.sll_protocol = htons(ETH_P_ALL); sll.sll_ifindex = (int)idx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[ERR] bind(%s) 실패: %s\n", g.iface, strerror(errno)); close(fd); return -1;
    }
    if (g.promisc) {
        struct packet_mreq mr; memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = (int)idx; mr.mr_type = PACKET_MR_PROMISC;
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    }
    int rb = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
    return fd;
}

static int rate_ok(int64_t now)
{
    if (g.max_pps <= 0) return 1;
    static double tokens = -1; static int64_t last;
    if (tokens < 0) { tokens = g.max_pps; last = now; }
    tokens += (double)(now - last) * g.max_pps / 1000.0; last = now;
    if (tokens > g.max_pps) tokens = g.max_pps;
    if (tokens < 1.0) return 0;
    tokens -= 1.0; return 1;
}

/* PACKET 메시지 생성 (정의서 2.5.1). length = raw_data 바이트 수(=캡처 길이) */
static struct msg *build_packet(const uint8_t *p, size_t caplen, const uint8_t *stmac)
{
    struct msg *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    char ts[40], st[18];
    gen_uuid(m->id, sizeof(m->id)); now_rfc3339(ts, sizeof(ts)); mac_str(stmac, st);

    size_t jcap = 512 + strlen(g_ap_esc) + strlen(g_if_esc) + caplen * 2;
    m->json = malloc(jcap);
    if (!m->json) { free(m); return NULL; }
    int n = snprintf(m->json, jcap,
        "{\"header\":{\"schema_version\":\"%s\",\"message_type\":\"PACKET\","
        "\"message_id\":\"%s\",\"generated_at\":\"%s\",\"ap_id\":\"%s\"},"
        "\"payload\":{\"packet\":{\"station_id\":\"%s\",\"interface\":\"%s\","
        "\"length\":%zu,\"raw_data\":\"",
        g.schema_version, m->id, ts, g_ap_esc, st, g_if_esc, caplen);
    static const char hx[] = "0123456789ABCDEF";
    for (size_t i = 0; i < caplen; i++) {
        m->json[n++] = hx[p[i] >> 4]; m->json[n++] = hx[p[i] & 0x0F];
    }
    n += snprintf(m->json + n, jcap - (size_t)n, "\"}}}");
    m->jlen = (size_t)n;
    return m;
}

static void capture_read(void)
{
    int64_t now = mono_ms();
    for (int i = 0; i < 128; i++) {
        struct sockaddr_ll sll; socklen_t sl = sizeof(sll);
        ssize_t r = recvfrom(g_capfd, pkt, PKT_SZ, MSG_DONTWAIT, (struct sockaddr *)&sll, &sl);
        if (r < 0) { if (errno != EAGAIN && errno != EINTR) LOGE("capture recv 오류: %s", strerror(errno)); break; }
        if (sll.sll_pkttype == PACKET_OUTGOING && !g.include_outgoing) continue;
        if (r < 14) continue;
        S.captured++;
        if (is_own_traffic(pkt, (size_t)r)) { S.own_skipped++; continue; }
        if (!filter_match(pkt, (size_t)r))  { S.filtered++; continue; }
        if (!rate_ok(now))                  { S.dropped_rate++; continue; }

        size_t caplen = (size_t)r > (size_t)g.snaplen ? (size_t)g.snaplen : (size_t)r;
        const uint8_t *stmac = strcasecmp(g.station_id_mode, "dst") ? pkt + 6 : pkt;
        struct msg *m = build_packet(pkt, caplen, stmac);
        if (!m) { LOGE("메모리 부족"); continue; }
        q_push_back(m); S.queued++;
    }
}

/* ---------------------------------------------------------------- 연결 */
static void set_backoff_next(int64_t now)
{
    next_conn_ms = now + backoff_ms;
    backoff_ms = backoff_ms * 2 > g.reconnect_max_ms ? g.reconnect_max_ms : backoff_ms * 2;
}

static void conn_close(const char *why)
{
    int64_t now = mono_ms();
    if (sfd >= 0) { close(sfd); sfd = -1; }
    if (cst == ST_CONNECTED) S.disconnects++;
    LOGI("연결 종료/실패: %s (in-flight %d건 재큐잉, 다음 재연결 %dms 후)", why, ninfl, backoff_ms);
    for (int i = ninfl - 1; i >= 0; i--) { infl[i]->tx_cnt = 0; infl[i]->need_tx = 0; q_push_front(infl[i]); }
    ninfl = 0; txlen = txoff = 0; rxlen = 0;
    cst = ST_DISC;
    set_backoff_next(now);
}

static void on_connected(void)
{
    cst = ST_CONNECTED; backoff_ms = g.reconnect_min_ms;
    txlen = txoff = 0; rxlen = 0; S.connects++;
    LOGI("서버 연결됨 %s:%d (queue=%zu)", g.server_ip, g.server_port, qcount);
}

static void start_connect(void)
{
    int64_t now = mono_ms();
    sfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sfd < 0) { LOGE("socket 실패: %s", strerror(errno)); set_backoff_next(now); return; }
    int on = 1;
    setsockopt(sfd, SOL_SOCKET,  SO_KEEPALIVE,  &on, sizeof(on));
    setsockopt(sfd, IPPROTO_TCP, TCP_KEEPIDLE,  &g.ka_idle,  sizeof(int));
    setsockopt(sfd, IPPROTO_TCP, TCP_KEEPINTVL, &g.ka_intvl, sizeof(int));
    setsockopt(sfd, IPPROTO_TCP, TCP_KEEPCNT,   &g.ka_cnt,   sizeof(int));
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY,   &on, sizeof(on));
    int rc = connect(sfd, (struct sockaddr *)&g_srv, sizeof(g_srv));
    if (rc == 0) { on_connected(); return; }
    if (errno == EINPROGRESS) { cst = ST_CONNECTING; conn_deadline_ms = now + g.connect_timeout_ms; return; }
    close(sfd); sfd = -1;
    LOGI("connect 실패: %s", strerror(errno));
    set_backoff_next(now);
}

/* ---------------------------------------------------------------- 송신 */
static int tx_room(size_t need)
{
    if (txcap - txlen >= need) return 1;
    if (txoff > 0) {
        memmove(txb, txb + txoff, txlen - txoff); txlen -= txoff; txoff = 0;
        if (txcap - txlen >= need) return 1;
    }
    return 0;
}

static void tx_put(const struct msg *m)
{
    if (g.framing == FRAMING_LENGTH) {
        uint32_t be = htonl((uint32_t)m->jlen); memcpy(txb + txlen, &be, 4); txlen += 4;
    }
    memcpy(txb + txlen, m->json, m->jlen); txlen += m->jlen;
    if (g.framing == FRAMING_NEWLINE) txb[txlen++] = '\n';
}

static int tx_flush(void)
{
    while (txoff < txlen) {
        ssize_t r = send(sfd, txb + txoff, txlen - txoff, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        txoff += (size_t)r;
    }
    txoff = txlen = 0;
    return 0;
}

static void pump(void)
{
    if (cst != ST_CONNECTED) return;
    int64_t now = mono_ms();
    size_t need = 0;

    /* 1) 재전송 (동일 message_id, 동일 데이터: 정의서 6.1) */
    for (int i = 0; i < ninfl; i++) {
        if (!infl[i]->need_tx) continue;
        need = infl[i]->jlen + 5;
        if (!tx_room(need)) return;
        tx_put(infl[i]);
        infl[i]->need_tx = 0; infl[i]->tx_cnt++;
        infl[i]->deadline_ms = now + g.ack_timeout_ms;
        S.retrans++;
    }
    /* 2) 신규 */
    while (qcount > 0 && (!g.wait_ack || ninfl < g.window)) {
        struct msg *m = q[qhead];
        if (!tx_room(m->jlen + 5)) break;
        tx_put(m);
        qhead = (qhead + 1) % qcap; qcount--;
        S.sent++;
        if (g.wait_ack) { m->tx_cnt = 1; m->deadline_ms = now + g.ack_timeout_ms; infl[ninfl++] = m; }
        else msg_free(m);
    }
    if (tx_flush() < 0) conn_close("send 오류");
}

/* ---------------------------------------------------------------- 수신/ACK */
static int extract_json(const char *buf, size_t len, size_t *start)
{
    int depth = 0, in_str = 0, esc = 0; size_t s = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i];
        if (in_str) { if (esc) esc = 0; else if (ch == '\\') esc = 1; else if (ch == '"') in_str = 0; continue; }
        if (ch == '"') { in_str = 1; continue; }
        if (ch == '{') { if (depth == 0) s = i; depth++; }
        else if (ch == '}' && depth > 0 && --depth == 0) { *start = s; return (int)(i - s + 1); }
    }
    return 0;
}

static int json_get_str(const char *json, const char *key, char *out, size_t sz)
{
    char pat[96]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < sz) { if (*p == '\\' && p[1]) p++; out[o++] = *p++; }
    out[o] = '\0'; return 0;
}

static int json_get_bool(const char *json, const char *key, int def)
{
    char pat[96]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (!strncmp(p, "true", 4)) return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return def;
}

static void infl_remove(int i)
{
    msg_free(infl[i]);
    memmove(&infl[i], &infl[i + 1], (size_t)(ninfl - i - 1) * sizeof(infl[0]));
    ninfl--;
}

static void handle_message(const char *json)
{
    char mtype[32] = "", aid[64] = "", status[32] = "";
    json_get_str(json, "message_type", mtype, sizeof(mtype));
    if (strcasecmp(mtype, "ACK")) { LOGD("ACK 외 메시지 수신(무시): type=%s", mtype); return; }
    json_get_str(json, "acked_message_id", aid, sizeof(aid));
    json_get_str(json, "status", status, sizeof(status));

    int idx = -1;
    for (int i = 0; i < ninfl; i++) if (!strcmp(infl[i]->id, aid)) { idx = i; break; }
    if (idx < 0) { LOGD("알 수 없는/지연 ACK: %s (%s)", aid, status); return; }

    /* status 표기가 정의서 내에서 불일치(STORED/SUCCESS/success) → 모두 허용 */
    if (!strcasecmp(status, "STORED") || !strcasecmp(status, "SUCCESS")) { S.acked++; infl_remove(idx); }
    else if (!strcasecmp(status, "DUPLICATE")) { S.dup++; infl_remove(idx); }
    else if (!strcasecmp(status, "REJECTED")) {
        char code[64] = "", emsg[128] = "";
        json_get_str(json, "code", code, sizeof(code)); json_get_str(json, "message", emsg, sizeof(emsg));
        S.rejected++;
        LOGE("REJECTED id=%s code=%s msg=%s", aid, code, emsg);
        if (json_get_bool(json, "retryable", 1) && infl[idx]->tx_cnt <= g.max_retry) {
            infl[idx]->deadline_ms = mono_ms() + 1000;      /* 1초 후 타임아웃 경로로 재전송 */
        } else { S.dropped_reject++; infl_remove(idx); }
    } else { LOGE("알 수 없는 ACK status '%s' → 폐기", status); S.dropped_reject++; infl_remove(idx); }
}

static void rx_process(void)
{
    ssize_t r = recv(sfd, rxb + rxlen, sizeof(rxb) - rxlen, 0);
    if (r == 0) { conn_close("서버가 연결 종료"); return; }
    if (r < 0) { if (errno == EAGAIN || errno == EINTR) return; conn_close(strerror(errno)); return; }
    rxlen += (size_t)r;

    for (;;) {
        if (g.framing == FRAMING_LENGTH) {
            if (rxlen < 4) break;
            uint32_t n; memcpy(&n, rxb, 4); n = ntohl(n);
            if (n > sizeof(rxb) - 4) { conn_close("잘못된 길이 헤더"); return; }
            if (rxlen < 4 + (size_t)n) break;
            memcpy(tmpj, rxb + 4, n); tmpj[n] = '\0';
            handle_message(tmpj);
            memmove(rxb, rxb + 4 + n, rxlen - 4 - n); rxlen -= 4 + n;
        } else {
            size_t st = 0; int jl = extract_json((char *)rxb, rxlen, &st);
            if (!jl) {
                if (!memchr(rxb, '{', rxlen) || rxlen == sizeof(rxb)) rxlen = 0;
                break;
            }
            memcpy(tmpj, rxb + st, (size_t)jl); tmpj[jl] = '\0';
            handle_message(tmpj);
            size_t used = st + (size_t)jl;
            memmove(rxb, rxb + used, rxlen - used); rxlen -= used;
        }
        if (cst != ST_CONNECTED) return;
    }
}

static void check_timeouts(void)
{
    if (cst != ST_CONNECTED || !g.wait_ack) return;
    int64_t now = mono_ms();
    for (int i = 0; i < ninfl; i++) {
        struct msg *m = infl[i];
        if (m->need_tx || now < m->deadline_ms) continue;
        if (m->tx_cnt > g.max_retry) { conn_close("ACK 미수신 (재전송 한도 초과, 재연결)"); return; }
        LOGD("ACK timeout id=%s tx=%d → 재전송", m->id, m->tx_cnt);
        m->need_tx = 1;
    }
}

/* ---------------------------------------------------------------- 운영 */
static void on_sig(int s) { if (s == SIGHUP) g_hup = 1; else g_stop = 1; }

static int daemonize(void)
{
    pid_t p = fork(); if (p < 0) return -1; if (p > 0) _exit(0);
    if (setsid() < 0) return -1;
    p = fork(); if (p < 0) return -1; if (p > 0) _exit(0);
    umask(027);
    if (chdir("/") < 0) {}
    int nul = open("/dev/null", O_RDWR);
    if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); if (nul > 2) close(nul); }
    return 0;
}

static int pidfile_create(void)
{
    if (!g.pidfile[0]) return 0;
    g_pidfd = open(g.pidfile, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (g_pidfd < 0) { LOGE("pidfile open 실패: %s", strerror(errno)); return -1; }
    if (flock(g_pidfd, LOCK_EX | LOCK_NB) < 0) { LOGE("이미 실행 중 (pidfile lock)"); return -1; }
    char b[32]; int n = snprintf(b, sizeof(b), "%d\n", getpid());
    if (ftruncate(g_pidfd, 0) < 0 || write(g_pidfd, b, (size_t)n) < 0) {}
    return 0;
}

static void log_stats(void)
{
    LOGI("stats: cap=%llu filt=%llu own=%llu queued=%llu sent=%llu acked=%llu dup=%llu rej=%llu "
         "retrans=%llu drop(queue=%llu rate=%llu rej=%llu) conn=%llu disc=%llu | pending=%zu inflight=%d state=%d",
         (unsigned long long)S.captured, (unsigned long long)S.filtered, (unsigned long long)S.own_skipped,
         (unsigned long long)S.queued, (unsigned long long)S.sent, (unsigned long long)S.acked,
         (unsigned long long)S.dup, (unsigned long long)S.rejected, (unsigned long long)S.retrans,
         (unsigned long long)S.dropped_queue, (unsigned long long)S.dropped_rate, (unsigned long long)S.dropped_reject,
         (unsigned long long)S.connects, (unsigned long long)S.disconnects, qcount, ninfl, (int)cst);
}

int main(int argc, char **argv)
{
    const char *cfgpath = "/etc/xgw/xgw_agent.conf"; int force_fg = 0, opt;
    while ((opt = getopt(argc, argv, "c:fh")) != -1) {
        if (opt == 'c') cfgpath = optarg;
        else if (opt == 'f') force_fg = 1;
        else { fprintf(stderr, "Usage: %s [-f] [-c config]\n", argv[0]); return opt == 'h' ? 0 : 1; }
    }

    cfg_defaults();
    if (cfg_load(cfgpath) < 0 || resolve_ap_id() < 0) return 1;
    json_escape(g.ap_id, g_ap_esc, sizeof(g_ap_esc));
    json_escape(g.iface, g_if_esc, sizeof(g_if_esc));
    g_urandom = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    /* 실패 시 터미널에 오류가 보이도록 데몬화 전에 캡처 소켓 오픈 */
    g_capfd = capture_open();
    if (g_capfd < 0) return 2;

    qcap = (size_t)g.queue_max;
    q = calloc(qcap, sizeof(*q));
    txcap = (size_t)(2 * (2 * g.snaplen + 1024)); if (txcap < 262144) txcap = 262144;
    txb = malloc(txcap);
    if (!q || !txb) { fprintf(stderr, "메모리 부족\n"); return 2; }

    g_daemon = (g.daemonize && !force_fg);
    if (g_daemon) {
        if (daemonize() < 0) { fprintf(stderr, "daemonize 실패\n"); return 2; }
        if (!g.log_file[0]) openlog("xgw_agent", LOG_PID, LOG_DAEMON);
    }
    log_open();
    if (pidfile_create() < 0) return 2;

    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_sig;
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL); sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    LOGI("xgw_agent 시작: if=%s ap_id=%s → %s:%d framing=%d wait_ack=%d window=%d snaplen=%d queue=%zu",
         g.iface, g.ap_id, g.server_ip, g.server_port, (int)g.framing, g.wait_ack, g.window, g.snaplen, qcap);

    backoff_ms = g.reconnect_min_ms;
    int64_t last_stats = mono_ms();

    while (!g_stop) {
        int64_t now = mono_ms();
        if (g_hup) { g_hup = 0; log_open(); LOGI("SIGHUP: 로그 재오픈"); }

        if (cst == ST_DISC && now >= next_conn_ms) start_connect();
        if (cst == ST_CONNECTING && now >= conn_deadline_ms) conn_close("connect timeout");

        struct pollfd pfd[2]; int n = 0;
        pfd[n].fd = g_capfd; pfd[n].events = POLLIN; pfd[n].revents = 0; n++;
        int si = -1;
        if (sfd >= 0) {
            si = n; pfd[n].fd = sfd; pfd[n].revents = 0;
            pfd[n].events = POLLIN | ((cst == ST_CONNECTING || txoff < txlen) ? POLLOUT : 0);
            n++;
        }
        int pr = poll(pfd, (nfds_t)n, 100);
        if (pr < 0 && errno != EINTR) { LOGE("poll 오류: %s", strerror(errno)); break; }

        if (pr > 0) {
            if (pfd[0].revents & POLLIN) capture_read();
            if (si >= 0 && sfd >= 0) {
                short re = pfd[si].revents;
                if (cst == ST_CONNECTING && (re & (POLLOUT | POLLERR | POLLHUP))) {
                    int err = 0; socklen_t el = sizeof(err);
                    getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err, &el);
                    if (err) conn_close(strerror(err)); else on_connected();
                } else if (cst == ST_CONNECTED) {
                    if (re & POLLIN) rx_process();
                    else if (re & (POLLERR | POLLHUP)) conn_close("소켓 오류/HUP");
                }
            }
        }
        check_timeouts();
        pump();

        if (g.stats_interval_sec > 0 && mono_ms() - last_stats >= g.stats_interval_sec * 1000LL) {
            log_stats(); last_stats = mono_ms();
        }
    }

    LOGI("종료 신호 수신, 정리 (미전송 큐 %zu건 / in-flight %d건 폐기)", qcount, ninfl);
    log_stats();
    if (sfd >= 0) close(sfd);
    close(g_capfd);
    if (g_pidfd >= 0) { unlink(g.pidfile); close(g_pidfd); }
    return 0;
}
