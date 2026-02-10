# NVD API 2.0 CVE 수집기

이 저장소는 NVD API 2.0에서 CVE를 수집해 PostgreSQL에 저장하는 기본 프로젝트입니다.

## 1) 준비

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.sample .env
```

`.env`에 실제 값 입력:
- `NVD_API_KEY`
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- `INITIAL_LOOKBACK_YEARS` (기본 5)
- `INCREMENTAL_WINDOW_DAYS` (기본 14)

## 2) PostgreSQL 컨테이너 실행 (Docker Compose)

프로젝트 루트의 `docker-compose.yml`은 `.env`의 DB 값을 사용합니다.

```bash
docker compose up -d
docker ps
```

필요 시 PostgreSQL 준비 상태 확인:

```bash
docker compose exec postgres pg_isready -U $DB_USER -d $DB_NAME
```

## 3) DB 스키마 생성

```bash
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f db_schema.sql
```

`cve_cpe` 정규화 테이블이 추가되었으므로, 스키마 적용 후 `initial` 또는 `incremental` 실행으로 CPE 데이터를 채워야 조회가 정확해집니다.

## 4) 실행

초기 적재 (최근 N년, 기본 5년):

```bash
python3 ingest_cves.py --mode initial
```

증분 적재 (lastModified 기준, 14일 청크):

```bash
python3 ingest_cves.py --mode incremental
```

## 5) 콘솔 조회 예시

```bash
python3 nvd_fetch.py --vendor ivanti --min-cvss 7.0
python3 nvd_fetch.py --product endpoint_manager_mobile --min-cvss 7.0
python3 nvd_fetch.py --vendor nginx --product nginx --min-cvss 7.0 --limit 20
python3 nvd_fetch.py --vendor ivanti --impact-type "Remote Code Execution" --min-cvss 7.0
python3 nvd_fetch.py --cpe-missing-only --sort-by last_modified --sort-order desc --limit 30
```

조건 규칙:
- `vendor`와 `product`를 모두 입력하면 AND 조건으로 검색
- 둘 중 하나만 입력하면 해당 단일 조건으로 검색
- `vendor`/`product` 없이도 검색 가능(전체 대상)
- 검색은 `ILIKE` 기반이라 대소문자 구분 없이 동작 (`Ivanti`, `ivanti` 동일)
- `--cpe-missing-only`를 사용하면 vulnerable CPE 매핑이 없는 CVE만 조회

## 6) 유틸리티 (기존 raw로 CPE 백필)

이미 적재된 `cve.raw`를 이용해 `cve_cpe`를 채울 수 있습니다(추가 API 호출 없음).

```bash
python3 -m utils.backfill_cpe_from_raw --config .env --batch-size 1000
python3 -m utils.backfill_impact_type --config .env --batch-size 1000
```

## 7) 웹 조회 페이지 실행

```bash
pip install -r requirements.txt
python3 web_app.py --host 0.0.0.0 --port 8888
```

브라우저에서 `http://<server-ip>:8888` 접속 후 조회할 수 있습니다.
초기 화면(필터 미입력)은 최신 `Last Modified` 순으로 자동 조회됩니다.

메뉴:
- `검색(/)` 페이지: CVE 조회
- `일일 검토(/daily)` 페이지: 프로필 규칙으로 전일/최근 24시간 대상 검토 및 상태 저장
- `설정(/settings)` 페이지: `본사(hq)`/`재화(jaehwa)` 프로필별 기본 검색값 저장

적용 우선순위:
- URL 파라미터 > 프로필 저장 설정(DB: `user_profile_settings`) > 하드코딩 기본값

지원 필터:
- `Last Modified Start/End` (날짜+시간 범위)
- `vendor`, `product`(쉼표 구분 OR), `keyword`(쉼표 구분 OR)
- `min_cvss`, `Impact Type`(다중 선택), `limit`
- `CPE Object`(설정 페이지에 등록한 `vendor:product[:version]` 목록을 on/off로 선택)
- `CPE missing only` (vulnerable CPE가 없는 CVE만)

일일 검토:
- 프로필 저장 규칙(`vendor`, `product`, `keyword`, `Impact Type`, `CPE Object`, `min_cvss`) 기반으로 자동 조회
- 기간 기준(`전일 마감`, `최근 24h`) + 기간(일) 선택 가능
- 행별 검토 상태(`미검토/검토완료/제외`)와 메모 저장
- 상태 필터(`전체/미검토/검토완료/제외`) 및 선택 항목 일괄 상태 변경 지원
- 설정 페이지에서 만든 활성 프리셋들을 OR 합집합으로 조회

설정 페이지 CPE UX:
- CPE 객체를 `vendor/product/version` 입력 후 추가
- 등록 목록은 칩으로 표시되며 즉시 삭제 가능
- `미리보기` 버튼으로 최근 N일 기준 예상 검토 대상 건수 확인
- `vendor/product/version` 입력란 자동완성 API (`/api/cpe/suggest`) 제공
- 현재 입력값을 프리셋으로 저장하고, 프리셋 활성/비활성/삭제 가능

표시/동작:
- `CVSS`는 등급+점수 칩으로 표시 (`None/Low/Medium/High/Critical`)
- 정렬은 테이블 헤더 `CVSS`, `Last Modified` 클릭으로 토글
- Description 상세는 오버레이로 표시(테이블 폭 고정)
- `Reset Filters`, `Share URL`, 행별 `Copy CVE`/`Copy CPE` 버튼 지원

개발 중 재시작 스크립트:
```bash
./dev_web.sh start --reload
./dev_web.sh restart --reload
./dev_web.sh stop
./dev_web.sh status
```

## 동작 원칙

- `raw` JSON을 DB(`cve.raw`)에 그대로 저장합니다.
- 제품/벤더 조회를 위해 CPE 정보를 `cve_cpe` 테이블로 정규화 저장합니다.
- 초기 적재는 `published` 기준 최근 `INITIAL_LOOKBACK_YEARS`만 수집합니다.
- 증분 적재는 `lastModified` 기준으로 조회하며, 14일 청크 단위로 안전하게 수집합니다.
- `cve.id` 기준 `UPSERT`로 신규/갱신을 반영합니다.

## 참고

- NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities

## 향후 과제

- 상세 목록은 `TODO.md`를 참고하세요.
