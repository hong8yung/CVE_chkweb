# TODO

## Utilities

- [ ] `utils/rebuild_cpe_for_recent.py` 추가: 최근 N일 CVE만 `cve_cpe` 재생성
- [ ] `utils/check_ingest_health.py` 추가: `ingest_job_log`, `ingest_checkpoint` 상태 점검
- [ ] `utils/reset_checkpoint.py` 추가: 증분 수집 시작 시점(`ingest_checkpoint`) 수동 조정

## Query

- [ ] `nvd_fetch.py` / 웹 조회에 description 옵션 검색(`--search-desc`) 추가하고, 결과에 `match_source`(`cpe`/`description`) 표시
- [ ] CPE 누락 CVE용 `affected_products_guess` DB화: 스키마(`text[]` + confidence/source) 추가, 백필 유틸 작성, 웹/CLI 검색 필터 연동

## Daily Review

- [ ] `/daily` 조회 소스를 기간 기반 `cve.last_modified` 결과가 아니라 `daily_review_backlog` 중심 누적 큐로 전환 (기간 밖 미검토 건도 계속 노출)
