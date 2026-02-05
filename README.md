# NVD API 2.0 CVE 조회 (Flask + HTML/JS)

이 저장소는 **NVD API 2.0**를 사용해 최신 CVE 정보를 가져오는 간단한 예제를 제공합니다.  
사용자가 **제품명**(예: `nginx`)과 **최소 CVSS 점수**를 입력하면, 조건에 맞는 취약점만 필터링해 보여주는 웹사이트를 만들기 위한 기반입니다.

아래는 **1단계: API 데이터를 콘솔에 출력하는 단계**부터 차근차근 진행하는 가이드입니다.

---

## 0) 준비 사항

- Python 3.10+
- `requests` 라이브러리

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 1) 콘솔에서 NVD API 2.0 호출하기

먼저 API로 데이터를 받아서 **콘솔에 출력**하는 스크립트를 실행합니다.

### 실행

```bash
python nvd_fetch.py --product nginx --min-cvss 7.0
```

### 기대 결과

- `nginx` 관련 CVE 목록이 출력됩니다.
- `min-cvss` 이상인 항목만 필터링합니다.

---

## 2) 다음 단계 (예고)

1. Flask로 검색 폼 생성
2. 서버에서 NVD API 호출
3. 결과를 HTML로 렌더링
4. 간단한 JS로 UX 개선

---

## 참고

- NVD API 2.0 공식 문서: https://nvd.nist.gov/developers/vulnerabilities
- API 키가 있으면 `NVD_API_KEY` 환경변수로 설정하면 제한이 완화됩니다.
