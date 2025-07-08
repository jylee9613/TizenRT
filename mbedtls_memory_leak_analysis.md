# mbedtls 메모리 누수 분석 보고서

## 개요
mbedtls 라이브러리 코드를 분석하여 메모리 누수(memory leak)가 발생할 수 있는 패턴들을 식별했습니다. 주요 취약점들과 개선 방안을 제시합니다.

## 주요 발견사항

### 1. SSL/TLS 핸드셰이크 초기화 과정에서의 메모리 누수 위험

**위치**: `external/mbedtls/ssl_tls.c:1090-1130`

**문제점**:
```c
// ssl_handshake_init 함수에서
if (ssl->transform_negotiate == NULL) {
    ssl->transform_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_transform));
}
if (ssl->session_negotiate == NULL) {
    ssl->session_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_session));
}
if (ssl->handshake == NULL) {
    ssl->handshake = mbedtls_calloc(1, sizeof(mbedtls_ssl_handshake_params));
}

// 에러 검사
if (ssl->handshake == NULL || 
    ssl->transform_negotiate == NULL ||
    ssl->session_negotiate == NULL) {
    // 일부 메모리만 해제하고 반환
    mbedtls_free(ssl->handshake);
    mbedtls_free(ssl->transform_negotiate);
    mbedtls_free(ssl->session_negotiate);
    return MBEDTLS_ERR_SSL_ALLOC_FAILED;
}
```

**위험도**: 중간
**개선 방안**: 
- 할당 실패 시 즉시 정리하는 패턴 사용
- 모든 할당을 한 번에 검증 후 실패 시 순차적 해제

### 2. X.509 인증서 체인 파싱에서의 메모리 누수

**위치**: `external/mbedtls/x509_crt.c:1015-1045, 1240-1250`

**문제점**:
```c
// x509_crt_parse_der_internal 함수에서
if (crt->version != 0 && crt->next == NULL) {
    crt->next = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (crt->next == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;  // 이전 할당들 정리 없음
    }
    // ...
}

ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx);
if (ret != 0) {
    if (prev) {
        prev->next = NULL;  // 포인터 연결만 해제, 메모리는 그대로
    }
    if (crt != chain) {
        mbedtls_free(crt);  // 구조체만 해제, 내부 할당된 메모리는?
    }
    return ret;
}
```

**위험도**: 높음
**개선 방안**:
- 인증서 파싱 실패 시 `mbedtls_x509_crt_free()` 호출
- 체인 요소별 완전한 정리 보장

### 3. PSA Crypto 키 슬롯 관리에서의 메모리 누수

**위치**: `external/mbedtls/psa_crypto.c:595-620`

**문제점**:
```c
psa_status_t psa_allocate_buffer_to_slot(psa_key_slot_t *slot,
                                         size_t buffer_length)
{
    if (slot->key.data != NULL) {
        return PSA_ERROR_ALREADY_EXISTS;  // 기존 메모리 해제 없이 에러 반환
    }

    slot->key.data = mbedtls_calloc(1, buffer_length);
    if (slot->key.data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    
    slot->key.bytes = buffer_length;
    return PSA_SUCCESS;
}
```

**위험도**: 중간
**개선 방안**:
- 기존 데이터 존재 시 명시적 해제 또는 재사용 정책 명확화
- 슬롯 상태 검증 강화

### 4. SSL 세션 복사에서의 부분적 메모리 누수

**위치**: `external/mbedtls/ssl_tls.c:270-320`

**문제점**:
```c
int mbedtls_ssl_session_copy(mbedtls_ssl_session *dst,
                             const mbedtls_ssl_session *src)
{
    if (src->peer_cert != NULL) {
        dst->peer_cert = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
        if (dst->peer_cert == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;  // 이미 할당된 다른 필드들 해제 없음
        }
        // ...
        if ((ret = mbedtls_x509_crt_parse_der(...)) != 0) {
            mbedtls_free(dst->peer_cert);  // 인증서 구조체만 해제
            dst->peer_cert = NULL;
            return ret;  // 다른 할당된 필드들은 그대로
        }
    }

    if (src->peer_cert_digest != NULL) {
        dst->peer_cert_digest = mbedtls_calloc(1, src->peer_cert_digest_len);
        if (dst->peer_cert_digest == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;  // 이전 할당들 정리 없음
        }
    }
}
```

**위험도**: 높음
**개선 방안**:
- 복사 과정에서 실패 시 이미 복사된 모든 리소스 정리
- 트랜잭션 방식의 복사 구현

### 5. 에러 처리 goto 패턴에서의 불완전한 정리

**다양한 파일에서 발견된 패턴**:
```c
// 일반적인 패턴
some_function() {
    ptr1 = mbedtls_calloc(...);
    ptr2 = mbedtls_calloc(...);
    
    if (error_condition) {
        goto cleanup;  // cleanup에서 일부 포인터만 해제하는 경우 있음
    }
    
cleanup:
    mbedtls_free(ptr1);  // ptr2 해제 누락 가능성
    return ret;
}
```

**위험도**: 중간
**개선 방안**:
- cleanup 라벨에서 모든 할당된 리소스의 체계적 해제
- NULL 포인터 검사 후 해제

## 고위험 패턴 요약

### 1. 에러 처리 경로에서의 메모리 해제 누락
- **파일**: ssl_tls.c, x509_crt.c, psa_crypto.c
- **원인**: 부분적 할당 후 실패 시 이미 할당된 메모리 해제 누락
- **영향**: 반복적 호출 시 메모리 누수 누적

### 2. 체인/링크 구조에서의 부분적 정리
- **파일**: x509_crt.c, ssl_tls.c
- **원인**: 연결된 구조체에서 일부 노드만 해제
- **영향**: 대용량 인증서 체인 처리 시 심각한 메모리 누수

### 3. 상태 불일치로 인한 메모리 누수
- **파일**: psa_crypto.c
- **원인**: 키 슬롯 상태와 실제 메모리 할당 상태 불일치
- **영향**: 키 관리 작업 반복 시 메모리 누수

## 권장 개선 사항

### 즉시 수정이 필요한 항목
1. **X.509 인증서 체인 파싱 함수 개선**
   - 모든 실패 경로에서 `mbedtls_x509_crt_free()` 호출 보장
   
2. **SSL 세션 복사 함수 개선**
   - 실패 시 부분적으로 복사된 모든 리소스 정리
   
3. **PSA 키 슬롯 관리 개선**
   - 기존 데이터 존재 시 명시적 해제 정책 구현

### 장기적 개선 방안
1. **메모리 관리 패턴 표준화**
   - RAII 스타일의 리소스 관리 도입
   - 자동 정리 매크로 활용

2. **정적 분석 도구 활용**
   - Valgrind, AddressSanitizer 등을 이용한 정기적 검증
   - 메모리 누수 검출 자동화

3. **단위 테스트 강화**
   - 메모리 누수 시나리오별 테스트 케이스 추가
   - 에러 주입 테스트를 통한 예외 상황 검증

## 결론

mbedtls 코드에서 발견된 메모리 누수 패턴들은 주로 복잡한 에러 처리 경로와 다중 할당 시나리오에서 발생합니다. 특히 SSL/TLS 핸드셰이크와 X.509 인증서 처리 부분에서 개선이 시급하며, 체계적인 리소스 관리 패턴 도입이 필요합니다.