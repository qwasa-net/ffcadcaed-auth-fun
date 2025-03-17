# ffcadcaed

Toy project to play with different authentication methods

+ service.py
+ client.py


## how to have fun

go outside and play

### virtual environment

```
make venv
make certs-create
make run-service
make run-client
```

### containers


```
make tea
```

#### Example output (redacted)


```
…
ffcadcaed-service | … [ERROR] [172.18.0.4:51354 ‖ python-httpx/0.28.1 ‖ client ‖ DEV.LOCAL/client-0548 ‖ client] KerberosAuth: failed
ffcadcaed-service | … [ERROR] [172.18.0.4:51354 ‖ python-httpx/0.28.1 ‖ client ‖ DEV.LOCAL/client-0548 ‖ client] 401 KerberosAuth: failed
ffcadcaed-service | 172.18.0.4 - - … "GET /hallo-there/ HTTP/1.1" 401 -
ffcadcaed-service | … [INFO] [172.18.0.4:51364 ‖ python-httpx/0.28.1 ‖ client ‖ DEV.LOCAL/client-0548 ‖ client ‖ CLIENT@DEV.LOCAL ‖ client] GET /hallo-there/
ffcadcaed-service | 172.18.0.4 - - … "GET /hallo-there/ HTTP/1.1" 200 -
…
ffcadcaed-client  | > [GET] https://service:3443/hallo-there/
ffcadcaed-client  | > host: service:3443
ffcadcaed-client  | > user-agent: python-httpx/0.28.1
ffcadcaed-client  | > x-api-key: client:1742717717
ffcadcaed-client  | > x-jwt: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGllbnQifQ.YwF9IBOHAvea0
ffcadcaed-client  | > x-hmac: Y2xpZW50:rRFvnD9fQwH1J2d/NlcoaWiyKVtJUYm/qS1WIiLeuLU=
ffcadcaed-client  | > authorization: Negotiate YIICxwYJKoZIhvcSAQICAQBuggK2MIICsqADAgEFoQMCAQ6iBwMFAAAAAACjggHLYYIBxz
ffcadcaed-client  |
ffcadcaed-client  | < [200]
ffcadcaed-client  | < server: BaseHTTP/0.6 Python/3.11.2
ffcadcaed-client  | < content-type: text/plain; charset=utf-8
ffcadcaed-client  |
ffcadcaed-client  | Hallo there !!
ffcadcaed-client  |
ffcadcaed-client  | IPAuth          : 172.18.0.4:51354
ffcadcaed-client  | UAAuth          : python-httpx/0.28.1
ffcadcaed-client  | APIKeyAuth      : client
ffcadcaed-client  | MTLSAuth        : DEV.LOCAL/client-0548
ffcadcaed-client  | JWTAuth         : client
ffcadcaed-client  | KerberosAuth    : CLIENT@DEV.LOCAL
ffcadcaed-client  | HMACAuth        : client
ffcadcaed-client  |

```

------------------

## Некоторые измышления на тему аутентификации от GitHub Copilot

### Сравнительная таблица методов аутентификации

| Метод          | Дополнительная инфраструктура | Аутентификация на стороне сервера | Получение токена на стороне клиента | Локальная обработка на сервере | Дополнительные действия для авторизации | Как передается токен |
|-----|-----|-----|-----|-----|-----|-----|
| **API Keys**   | Нет (локальная конфигурация) или база данных для проверки ключей и прав. Генерация ключей возможна локально или однократно при разворачивании системы | Проверка ключа в базе данных или конфигурации | Выдача ключа администратором или при регистрации | Да, если ключи хранятся локально | Проверка прав доступа, связанных с ключом. Локально, если права указаны в конфигурации; обращение к базе данных для проверки прав, если они не указаны в конфигурации | В заголовке HTTP-запроса |
| **HTTP Basic Authentication** | Нет (локальная конфигурация) или база данных для проверки учетных данных и прав | Проверка логина и пароля в базе данных или конфигурации | Передача логина и пароля в заголовке Authorization | Да, если учетные данные хранятся локально | Проверка прав доступа, связанных с учетными данными. Локально, если права указаны в конфигурации; обращение к базе данных для проверки прав, если они не указаны в конфигурации | В заголовке Authorization, закодированном в Base64 |
| **JWT**        | Нет (локальная конфигурация) или база данных для проверки прав, если они не указаны в токене. Генерация токенов возможна локально | Расшифровка токена и/или проверка подписи | Генерация токена при аутентификации пользователя на основании учетных данных и ролей | Да, если ключ расшифровки известен серверу | Проверка ролей и прав в payload токена. Локально, если права указаны в токене; обращение к базе данных для проверки прав, если они не указаны в токене | В заголовке Authorization с использованием схемы Bearer |
| **Session Keys** | Да, сервер базы данных для хранения сессий. Генерация сессионных ключей требует начальной аутентификации с использованием других методов (например, логин/пароль, OAuth) | Проверка сессионного ключа в базе данных | Генерация сессионного ключа при входе пользователя после успешной аутентификации | Нет, требуется обращение к базе данных | Проверка прав доступа, связанных с сессией. Обращение к базе данных для проверки прав | В заголовке Authorization или в cookie |
| **mTLS**       | Да (CA для выдачи сертификатов: OpenSSL, Let's Encrypt, HashiCorp Vault …), сервер базы данных для проверки прав, если они не указаны в сертификате. Генерация сертификатов возможна локально или однократно при разворачивании системы | Проверка клиентского сертификата | Получение сертификата от CA | Да, если сертификаты и CA известны серверу | Проверка прав доступа, связанных с сертификатом. Локально, если права указаны в сертификате; обращение к базе данных для проверки прав, если они не указаны в сертификате | В процессе установления TLS-соединения |
| **Kerberos**   | Да (KDC сервер, например, MIT Kerberos, Windows AD), сервер базы данных или LDAP для проверки прав. Генерация токенов требует KDC | Проверка токена с использованием локального keytab | Получение токена от KDC при входе в систему | Да, если keytab хранится локально | Проверка прав доступа в базе данных или LDAP. Локально, если права указаны в токене; обращение к базе данных или LDAP для проверки прав, если они не указаны в токене | В заголовке Authorization с использованием схемы Negotiate |
| **OAuth 2.0**  | Да (Authorization Server, например, Keycloak, Auth0), сервер базы данных для проверки прав. Генерация токенов требует Authorization Server | Обращение к Authorization Server для проверки токена | Получение токена от Authorization Server с использованием различных грантов | Нет, требуется обращение к Authorization Server | Проверка прав доступа, связанных с токеном. Обращение к Authorization Server для проверки прав | В заголовке Authorization с использованием схемы Bearer |
| **OpenID Connect** | Да (Identity Provider, например, Keycloak, Auth0, Google Identity Platform), сервер базы данных для проверки прав. Генерация токенов требует Identity Provider | Обращение к Identity Provider для проверки токена | Получение токена от Identity Provider после аутентификации пользователя | Нет, требуется обращение к Identity Provider | Проверка прав доступа, связанных с токеном. Обращение к Identity Provider для проверки прав | В заголовке Authorization с использованием схемы Bearer |
| **SAML**       | Да (Identity Provider, например, Okta, OneLogin), сервер базы данных для проверки прав. Генерация токенов требует Identity Provider | Обращение к Identity Provider для проверки SAML Assertion | Получение SAML Assertion от Identity Provider после аутентификации пользователя | Нет, требуется обращение к Identity Provider | Проверка прав доступа, связанных с SAML Assertion. Обращение к Identity Provider для проверки прав | В теле HTTP-запроса или в заголовке Authorization |
| **HMAC**       | Нет (локальная конфигурация) или база данных для проверки прав, если они не указаны в токене. Генерация ключей возможна локально или однократно при разворачивании системы | Проверка HMAC подписи с использованием секретного ключа | Генерация HMAC подписи с использованием секретного ключа | Да, если секретный ключ известен серверу | Проверка прав доступа, связанных с HMAC подписью. Локально, если права указаны в конфигурации; обращение к базе данных для проверки прав, если они не указаны в конфигурации | В заголовке HTTP-запроса или в параметрах URL |

### Рекомендации

Для вашей ситуации, если все сервисы находятся внутри одной системы и учетные записи известны заранее, наилучшим выбором будет **JWT** или **API Keys**, так как они требуют минимальной дополнительной инфраструктуры и просты в реализации. Эти методы также позволяют полностью локальную обработку на сервере, что упрощает управление и повышает производительность.

