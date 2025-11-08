# 소셜 로그인 (Google, Naver, Kakao)
## 개요
소셜/일반 로그인 모두 Cookie 기반으로 토큰 서빙하는 소셜 로그인 BE 작업물이다.

소셜은 쿠키 기반인데 일반 로그인은 JSON에 토큰이 실어 내보내는게 다반사다.  
서로 처리 방식이 다르다보니까, RTR (Rotate Refresh Token)이나 그냥 토큰 처리할 때 등등 상당히 번거롭다.

그래서 소셜/일반 로그인 모두 쿠키 기반으로 토큰을 받아오도록 설계했다.

## 사용법
.env 만들고 application.yml에 있는 환경변수 값을 채운다.  
그런 다음 IDE에 .env 적용한다. (Run > EditConfiguration > Modify Options > Environment Variables)

아니면 .env 안만들고 일일이 Environment Variables에 환경변수 등록하는 방법도 있다.

## 테스트
Swagger API 명세서를 기반으로 테스트한다.  
@Test-Sceanrios 의 경우는, 브라우저 및 API 테스트한 과정들을 담은 노션 페이지이다.

- [@Swagger](http://localhost:8080/swagger-ui/index.html$0)
- [@Test-Scenarios](https://hooby.notion.site/Deokive-Social-Login-Test-28af6c063f3e80bca0b3ef66eb4b356a?source=copy_link)

## 프론트 레포
- [@Frontend-Repo](https://github.com/Youcu/jwt-social-login$0)