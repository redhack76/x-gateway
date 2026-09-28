/*
 * xgw_seclog_test.c
 * X-Gateway 보안로그(PACKET) 전송 테스트 클라이언트
 *
 * 기준 문서 : X-Gateway 보안로그 / Wi-Fi 정책 연동 정의서 H1Radio v0.1 (미완성본)
 * 전송 규격 : TCP 지속연결(+keepalive), UTF-8 JSON
 * 대상      : Wi-Fi Gateway -> 보안 로그 수집 Agent (기본 183.99.77.198:50010)
 *
 * 모든 설정은 config 파일에서 읽는다.
 *
 * Build : gcc -O2 -Wall -Wextra -o xgw_seclog_test xgw_seclog_test.c
 * Run   : ./xgw_seclog_test [config_file]      (기본: ./xgw_seclog_test.conf)
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BUF_SZ        8192
#define RAW_HEX_MAX   4096
#define STR_SZ        128

/* 메시지 프레이밍 (정의서 미확정 항목 -> config로 선택) */
enum framing { FRAMING_NEWLINE = 0, FRAMING_NONE, FRAMING_LENGTH };

struct config {
    char server_ip[64];
    int  server_port;
    int  connect_timeout_ms;
    int  ack_timeout_ms;
    int  max_retry;            /* ACK 미수신 시 동일 message_id 재전송 횟수 */
    int  wait_ack;             /* 1: ACK 대기, 0: 송신만 */
    int  send_count;           /* 전송 횟수 (0 = 무한) */
    int  send_interval_ms;
    enum framing framing;
    int  keepalive_idle;
    int  keepalive_intvl;
    int  keepalive_cnt;

    char schema_version[16];
    char ap_id[STR_SZ];
    char interface_name[STR_SZ];
    char station_id[STR_SZ];
    char raw_data[RAW_HEX_MAX + 1];   /* HEX 문자열. 비우면 ARP 샘플 사용 */
};

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* ------------------------------------------------------------------ */
/* 유틸                                                                */
/* ------------------------------------------------------------------ */
static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static void msleep(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR && !g_stop) {}
}

/* RFC 3339 UTC, ms 단위 (예: 2026-09-02T02:15:31.247Z) */
static void now_rfc3339(char *out, size_t sz)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, sz, "%s.%03dZ", base, (int)(ts.tv_nsec / 1000000L) % 1000);
}

/* UUID v4 */
static void gen_uuid(char *out, size_t sz)
{
    unsigned char b[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(b, 1, 16, f) != 16) {
        for (int i = 0; i < 16; i++) b[i] = (unsigned char)(rand() & 0xFF);
    }
    if (f) fclose(f);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, sz,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* JSON 문자열 이스케이프 (UTF-8 바이트는 그대로 통과) */
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

/* HEX 문자열 검증 및 바이트 길이 반환 (오류 시 -1) */
static int hex_byte_len(const char *h)
{
    size_t n = strlen(h);
    if (n == 0 || (n % 2) != 0) return -1;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)h[i])) return -1;
    return (int)(n / 2);
}

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */
static void config_defaults(struct config *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->server_ip, sizeof(c->server_ip), "183.99.77.198");
    c->server_port        = 50010;
    c->connect_timeout_ms = 5000;
    c->ack_timeout_ms     = 3000;
    c->max_retry          = 3;
    c->wait_ack           = 1;
    c->send_count         = 1;
    c->send_interval_ms   = 1000;
    c->framing            = FRAMING_NEWLINE;
    c->keepalive_idle     = 30;
    c->keepalive_intvl    = 10;
    c->keepalive_cnt      = 3;
    snprintf(c->schema_version, sizeof(c->schema_version), "1.0");
    snprintf(c->ap_id, sizeof(c->ap_id), "38:F4:5E:11:22:33");
    snprintf(c->interface_name, sizeof(c->interface_name), "br-lan");
    snprintf(c->station_id, sizeof(c->station_id), "8C:AA:BB:CC:DD:EE");
    /* 정의서 2.5.1 ARP 샘플 (42 bytes) */
    snprintf(c->raw_data, sizeof(c->raw_data),
             "FFFFFFFFFFFF8CAABBCCDDEE080600010800060400018CAABBCCDDEE"
             "C0000215000000000000C0000201");
}

static int config_load(const char *path, struct config *c)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[ERR] config open 실패: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    char line[RAW_HEX_MAX + 256];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        char *eq = strchr(p, '=');
        if (!eq) {
            fprintf(stderr, "[WARN] config:%d '=' 없음, 무시\n", lineno);
            continue;
        }
        *eq = '\0';
        char *k = trim(p);
        char *v = trim(eq + 1);

        if      (!strcmp(k, "server_ip"))          snprintf(c->server_ip, sizeof(c->server_ip), "%s", v);
        else if (!strcmp(k, "server_port"))        c->server_port = atoi(v);
        else if (!strcmp(k, "connect_timeout_ms")) c->connect_timeout_ms = atoi(v);
        else if (!strcmp(k, "ack_timeout_ms"))     c->ack_timeout_ms = atoi(v);
        else if (!strcmp(k, "max_retry"))          c->max_retry = atoi(v);
        else if (!strcmp(k, "wait_ack"))           c->wait_ack = atoi(v);
        else if (!strcmp(k, "send_count"))         c->send_count = atoi(v);
        else if (!strcmp(k, "send_interval_ms"))   c->send_interval_ms = atoi(v);
        else if (!strcmp(k, "keepalive_idle"))     c->keepalive_idle = atoi(v);
        else if (!strcmp(k, "keepalive_intvl"))    c->keepalive_intvl = atoi(v);
        else if (!strcmp(k, "keepalive_cnt"))      c->keepalive_cnt = atoi(v);
        else if (!strcmp(k, "framing")) {
            if      (!strcasecmp(v, "newline")) c->framing = FRAMING_NEWLINE;
            else if (!strcasecmp(v, "none"))    c->framing = FRAMING_NONE;
            else if (!strcasecmp(v, "length"))  c->framing = FRAMING_LENGTH;
            else fprintf(stderr, "[WARN] config:%d 알 수 없는 framing '%s'\n", lineno, v);
        }
        else if (!strcmp(k, "schema_version"))     snprintf(c->schema_version, sizeof(c->schema_version), "%s", v);
        else if (!strcmp(k, "ap_id"))              snprintf(c->ap_id, sizeof(c->ap_id), "%s", v);
        else if (!strcmp(k, "interface"))          snprintf(c->interface_name, sizeof(c->interface_name), "%s", v);
        else if (!strcmp(k, "station_id"))         snprintf(c->station_id, sizeof(c->station_id), "%s", v);
        else if (!strcmp(k, "raw_data"))           snprintf(c->raw_data, sizeof(c->raw_data), "%s", v);
        else fprintf(stderr, "[WARN] config:%d 알 수 없는 키 '%s'\n", lineno, k);
    }
    fclose(fp);

    if (hex_byte_len(c->raw_data) < 0) {
        fprintf(stderr, "[ERR] raw_data는 짝수 길이의 HEX 문자열이어야 합니다.\n");
        return -1;
    }
    if (c->server_port <= 0 || c->server_port > 65535) {
        fprintf(stderr, "[ERR] server_port 범위 오류: %d\n", c->server_port);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Socket                                                              */
/* ------------------------------------------------------------------ */
static int tcp_connect(const struct config *c)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)c->server_port);
    if (inet_pton(AF_INET, c->server_ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "[ERR] server_ip 형식 오류: %s\n", c->server_ip);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) {
        perror("connect"); close(fd); return -1;
    }
    if (rc < 0) {
        fd_set wf;
        struct timeval tv = { c->connect_timeout_ms / 1000,
                              (c->connect_timeout_ms % 1000) * 1000 };
        FD_ZERO(&wf); FD_SET(fd, &wf);
        rc = select(fd + 1, NULL, &wf, NULL, &tv);
        if (rc <= 0) {
            fprintf(stderr, "[ERR] connect timeout/오류 (%s:%d)\n", c->server_ip, c->server_port);
            close(fd); return -1;
        }
        int err = 0; socklen_t el = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) {
            fprintf(stderr, "[ERR] connect 실패: %s\n", strerror(err));
            close(fd); return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);   /* blocking 복귀 */

    /* 지속연결 + TCP keepalive (정의서 2.4) */
    int on = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,  &on, sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &c->keepalive_idle,  sizeof(int));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &c->keepalive_intvl, sizeof(int));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &c->keepalive_cnt,   sizeof(int));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,   &on, sizeof(on));
    return fd;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int send_framed(int fd, enum framing fr, const char *json, size_t len)
{
    switch (fr) {
    case FRAMING_LENGTH: {
        uint32_t be = htonl((uint32_t)len);
        if (send_all(fd, &be, 4) < 0) return -1;
        return send_all(fd, json, len);
    }
    case FRAMING_NEWLINE:
        if (send_all(fd, json, len) < 0) return -1;
        return send_all(fd, "\n", 1);
    case FRAMING_NONE:
    default:
        return send_all(fd, json, len);
    }
}

/* ------------------------------------------------------------------ */
/* ACK 수신 / 파싱                                                     */
/* ------------------------------------------------------------------ */
/* 수신 버퍼에서 JSON 1개 추출 (중괄호 매칭, 문자열 내부 무시). 성공 시 길이 반환 */
static int extract_json(const char *buf, size_t len, size_t *start)
{
    int depth = 0, in_str = 0, esc = 0;
    size_t s = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i];
        if (in_str) {
            if (esc) esc = 0;
            else if (ch == '\\') esc = 1;
            else if (ch == '"') in_str = 0;
            continue;
        }
        if (ch == '"') { in_str = 1; continue; }
        if (ch == '{') { if (depth == 0) s = i; depth++; }
        else if (ch == '}' && depth > 0) {
            if (--depth == 0) { *start = s; return (int)(i - s + 1); }
        }
    }
    return 0;
}

/* 단순 문자열 값 추출: "key" : "value" */
static int json_get_str(const char *json, const char *key, char *out, size_t sz)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < sz) {
        if (*p == '\\' && p[1]) p++;
        out[o++] = *p++;
    }
    out[o] = '\0';
    return 0;
}

static int json_get_bool(const char *json, const char *key, int def)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (!strncmp(p, "true", 4))  return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return def;
}

enum ack_result { ACK_OK = 0, ACK_DUP, ACK_REJ_RETRY, ACK_REJ_FATAL, ACK_TIMEOUT, ACK_CONN_ERR };

static enum ack_result wait_ack(int fd, const struct config *c, const char *msg_id)
{
    char buf[BUF_SZ];
    size_t have = 0;
    struct timespec t0, tn;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &tn);
        long el = (tn.tv_sec - t0.tv_sec) * 1000L + (tn.tv_nsec - t0.tv_nsec) / 1000000L;
        long remain = c->ack_timeout_ms - el;
        if (remain <= 0) return ACK_TIMEOUT;

        /* 버퍼에 이미 완성된 메시지가 있는지 확인 */
        const char *body = buf;
        size_t st = 0;
        int jl = 0;
        if (c->framing == FRAMING_LENGTH) {
            if (have >= 4) {
                uint32_t n; memcpy(&n, buf, 4); n = ntohl(n);
                if (n > BUF_SZ - 5) return ACK_CONN_ERR;
                if (have >= 4 + (size_t)n) { body = buf + 4; jl = (int)n; st = 0; }
            }
        } else {
            jl = extract_json(buf, have, &st);
        }

        if (jl > 0) {
            char json[BUF_SZ];
            memcpy(json, body + st, (size_t)jl);
            json[jl] = '\0';
            printf("[RX ] %s\n", json);

            char mtype[32] = "", aid[64] = "", status[32] = "";
            json_get_str(json, "message_type", mtype, sizeof(mtype));
            json_get_str(json, "acked_message_id", aid, sizeof(aid));
            json_get_str(json, "status", status, sizeof(status));

            /* 다른 메시지/다른 ID면 버리고 계속 대기 */
            size_t consumed = (c->framing == FRAMING_LENGTH) ? 4 + (size_t)jl : st + (size_t)jl;
            memmove(buf, buf + consumed, have - consumed);
            have -= consumed;

            if (strcasecmp(mtype, "ACK") != 0 || strcmp(aid, msg_id) != 0) {
                fprintf(stderr, "[WARN] 대상 ACK 아님 (type=%s, acked=%s) -> 계속 대기\n", mtype, aid);
                continue;
            }
            /* 정의서상 status 값 표기가 불일치(STORED/SUCCESS/success) -> 모두 허용 */
            if (!strcasecmp(status, "STORED") || !strcasecmp(status, "SUCCESS")) return ACK_OK;
            if (!strcasecmp(status, "DUPLICATE")) return ACK_DUP;
            if (!strcasecmp(status, "REJECTED")) {
                char ecode[64] = "", emsg[128] = "";
                json_get_str(json, "code", ecode, sizeof(ecode));
                json_get_str(json, "message", emsg, sizeof(emsg));
                fprintf(stderr, "[ACK] REJECTED code=%s msg=%s\n", ecode, emsg);
                return json_get_bool(json, "retryable", 1) ? ACK_REJ_RETRY : ACK_REJ_FATAL;
            }
            fprintf(stderr, "[WARN] 알 수 없는 ACK status: %s\n", status);
            return ACK_REJ_FATAL;
        }

        fd_set rf;
        struct timeval tv = { remain / 1000, (remain % 1000) * 1000 };
        FD_ZERO(&rf); FD_SET(fd, &rf);
        int rc = select(fd + 1, &rf, NULL, NULL, &tv);
        if (rc < 0) { if (errno == EINTR) continue; return ACK_CONN_ERR; }
        if (rc == 0) return ACK_TIMEOUT;

        ssize_t n = recv(fd, buf + have, sizeof(buf) - 1 - have, 0);
        if (n <= 0) {
            fprintf(stderr, "[ERR] 서버가 연결을 종료했거나 recv 오류\n");
            return ACK_CONN_ERR;
        }
        have += (size_t)n;
    }
}

/* ------------------------------------------------------------------ */
/* PACKET 메시지 생성 (정의서 2.5.1)                                    */
/* ------------------------------------------------------------------ */
static int build_packet_json(const struct config *c, const char *msg_id,
                             const char *ts, char *out, size_t sz)
{
    char sv[64], ap[STR_SZ * 2], st[STR_SZ * 2], ifn[STR_SZ * 2];
    json_escape(c->schema_version, sv, sizeof(sv));
    json_escape(c->ap_id, ap, sizeof(ap));
    json_escape(c->station_id, st, sizeof(st));
    json_escape(c->interface_name, ifn, sizeof(ifn));

    int n = snprintf(out, sz,
        "{"
          "\"header\":{"
            "\"schema_version\":\"%s\","
            "\"message_type\":\"PACKET\","
            "\"message_id\":\"%s\","
            "\"generated_at\":\"%s\","
            "\"ap_id\":\"%s\""
          "},"
          "\"payload\":{"
            "\"packet\":{"
              "\"station_id\":\"%s\","
              "\"interface\":\"%s\","
              "\"length\":%d,"
              "\"raw_data\":\"%s\""
            "}"
          "}"
        "}",
        sv, msg_id, ts, ap, st, ifn, hex_byte_len(c->raw_data), c->raw_data);
    return (n < 0 || (size_t)n >= sz) ? -1 : n;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *cfg_path = (argc > 1) ? argv[1] : "./xgw_seclog_test.conf";
    struct config cfg;
    config_defaults(&cfg);
    if (config_load(cfg_path, &cfg) < 0) return 1;

    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    printf("=== X-Gateway 보안로그 전송 테스트 ===\n");
    printf("config   : %s\n", cfg_path);
    printf("server   : %s:%d (TCP, UTF-8 JSON)\n", cfg.server_ip, cfg.server_port);
    printf("framing  : %s | wait_ack=%d | ack_timeout=%dms | max_retry=%d\n",
           cfg.framing == FRAMING_NEWLINE ? "newline" :
           cfg.framing == FRAMING_LENGTH  ? "length(4B BE)" : "none",
           cfg.wait_ack, cfg.ack_timeout_ms, cfg.max_retry);
    printf("ap_id    : %s | station_id: %s | if: %s | len: %d bytes\n\n",
           cfg.ap_id, cfg.station_id, cfg.interface_name, hex_byte_len(cfg.raw_data));

    int fd = tcp_connect(&cfg);
    if (fd < 0) return 2;
    printf("[OK ] connected\n");

    int sent_ok = 0, sent_fail = 0;

    for (int seq = 1; !g_stop && (cfg.send_count == 0 || seq <= cfg.send_count); seq++) {
        char msg_id[40], ts[40], json[BUF_SZ];
        gen_uuid(msg_id, sizeof(msg_id));
        now_rfc3339(ts, sizeof(ts));
        int jl = build_packet_json(&cfg, msg_id, ts, json, sizeof(json));
        if (jl < 0) { fprintf(stderr, "[ERR] JSON 버퍼 부족\n"); break; }

        int done = 0;
        /* 재전송 시 동일 message_id / 동일 데이터 사용 (정의서 6.1) */
        for (int attempt = 0; attempt <= cfg.max_retry && !done && !g_stop; attempt++) {
            printf("[TX ] #%d try=%d %s\n", seq, attempt, json);

            if (send_framed(fd, cfg.framing, json, (size_t)jl) < 0) {
                fprintf(stderr, "[ERR] send 실패 (%s) -> 재연결\n", strerror(errno));
                close(fd);
                fd = tcp_connect(&cfg);
                if (fd < 0) { msleep(1000); continue; }
                continue;
            }
            if (!cfg.wait_ack) { done = 1; sent_ok++; break; }

            enum ack_result r = wait_ack(fd, &cfg, msg_id);
            switch (r) {
            case ACK_OK:        printf("[ACK] #%d STORED\n", seq);    done = 1; sent_ok++; break;
            case ACK_DUP:       printf("[ACK] #%d DUPLICATE\n", seq); done = 1; sent_ok++; break;
            case ACK_REJ_FATAL: fprintf(stderr, "[ACK] #%d REJECTED(non-retryable)\n", seq);
                                done = 1; sent_fail++; break;
            case ACK_REJ_RETRY: fprintf(stderr, "[ACK] #%d REJECTED(retryable) -> 재전송\n", seq); break;
            case ACK_TIMEOUT:   fprintf(stderr, "[WARN] #%d ACK timeout -> 재전송\n", seq); break;
            case ACK_CONN_ERR:
                close(fd);
                fd = tcp_connect(&cfg);
                if (fd < 0) msleep(1000);
                break;
            }
        }
        if (!done) { fprintf(stderr, "[FAIL] #%d 재전송 한도 초과 (id=%s)\n", seq, msg_id); sent_fail++; }

        if (fd < 0) { fprintf(stderr, "[ERR] 서버 연결 불가, 종료\n"); break; }
        if (cfg.send_count == 0 || seq < cfg.send_count) msleep(cfg.send_interval_ms);
    }

    printf("\n=== 결과: 성공 %d / 실패 %d ===\n", sent_ok, sent_fail);
    if (fd >= 0) close(fd);
    return sent_fail ? 3 : 0;
}
