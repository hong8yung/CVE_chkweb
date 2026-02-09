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
python3 nvd_fetch.py --product nginx --min-cvss 7.0
```

## 동작 원칙

- `raw` JSON을 DB(`cve.raw`)에 그대로 저장합니다.
- 초기 적재는 `published` 기준 최근 `INITIAL_LOOKBACK_YEARS`만 수집합니다.
- 증분 적재는 `lastModified` 기준으로 조회하며, 14일 청크 단위로 안전하게 수집합니다.
- `cve.id` 기준 `UPSERT`로 신규/갱신을 반영합니다.

## 참고

- NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities
