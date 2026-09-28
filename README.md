# X-Gateway

X-Gateway 4세부 — Wi-Fi Gateway(AP) 보안 로그 수집/전송 Agent.
기준 문서: *X-Gateway 보안로그 / Wi-Fi 정책 연동 정의서 H1Radio v0.1* (미완성본)

## 구성

| 경로 | 설명 |
| --- | --- |
| `agent/xgw_agent.c` | AP용 상주 Agent. AF_PACKET 캡처 → PACKET(JSON) 생성 → TCP 전송, ACK/재전송/자동 재연결 |
| `tools/xgw_seclog_test.c` | 수집 서버 연동 테스트 클라이언트 (고정 샘플 전송) |
| `conf/xgw_agent.conf` | Agent 설정 예시 |
| `conf/xgw_seclog_test.conf` | 테스트 클라이언트 설정 예시 |
| `scripts/xgw_agent.init` | OpenWrt procd init 스크립트 |

## 빌드

```
make                                   # build/xgw_agent, build/xgw_seclog_test
make CROSS_COMPILE=<toolchain-prefix>-  # AP용 크로스 컴파일
```

## 실행

```
# 테스트 클라이언트 (기본 대상 183.99.77.198:50010)
./build/xgw_seclog_test conf/xgw_seclog_test.conf

# Agent (root 필요: AF_PACKET)
./build/xgw_agent -f -c conf/xgw_agent.conf    # -f: 포그라운드
```

AP 배포: `xgw_agent` → `/usr/sbin`, 설정 → `/etc/xgw/xgw_agent.conf`,
`scripts/xgw_agent.init` → `/etc/init.d/xgw_agent` 후 `enable && start`.

## 미확정 사항 (쿤텍 협의 필요)
- 메시지 프레이밍(`framing`: newline / length / none)
- ACK status 표기 (STORED / SUCCESS)
- `length` 의미 (캡처 길이 vs 원본 길이), `station_id` 산정 방식
- mTLS 적용, Wi-Fi 정책(POLICY) 수신 인터페이스(포트 미정)
