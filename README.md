**1. Иду в application.properties и вижу конфиги:**

```properties
jwt.secret=<секретный ключ в BASE64>
jwt.access.expiration.ms=<время жизни access токена в ms>
jwt.refresh.expiration.ms=<время жизни refresh токена в ms>
jwt.blacklist.cleanup.interval=<интервал очистки blacklist токенов в ms>
```

**2. При запуске приложения класс TestUserLoader добавляет тестовых юзеров**

```declarative
✅ Test users added (user/password, admin/admin123)
```

**3. Иду в Postman, POST запрос localhost:8080/api/v1/auth/login с телом:**

   ```json
   {
   "username": "user",
   "password": "password"
   }
   ```

**4. Получаю 200 OK + access токен и refresh токен:**

```json
{
   "accessToken": <access токен>,
   "refreshToken": <refresh токен>
}
```

**5. Отправляю GET запрос localhost:8080/api/v1/hello с заголовком:**

```declarative
Authorization: Bearer <полученный ранее токен>
```

**6. Получаю 200 OK + ответ:**

```declarative
Hello, user! =)
```

**7. Радуюсь**

```declarative
🥳
```

**8. Отправляю GET запрос localhost:8080/api/v1/auth/me с заголовком:**

```declarative
Authorization: Bearer <полученный ранее токен>
```

**9. Получаю инфу о пользователе:**

```json
{
   "username": "user",
   "roles": [
      "USER"
   ]
}
```

**10. Отправляю POST запрос localhost:8080/api/v1/auth/refresh с телом:**

```json
{
   "refreshToken": <полученный ранее refresh токен>
}
```

**11. Получаю новые access и refresh токены, старый refresh токен идёт в blacklist:**

```json
{
   "accessToken": <новый access токен>,
   "refreshToken": <новый refresh токен>
}
```

**12. Отправляю POST запрос localhost:8080/api/v1/auth/logout с телом:**

```declarative
Authorization: Bearer <полученный ранее access или refresh токен>
```

**13. Токены попадают в blacklist, получаем 200 OK + сообщение:**

```declarative
Logged out successfully
```

**14. При использовании некорректных или добавленных в blacklist токенов получаю одно из сообщений об ошибке:**

```declarative
Token is invalidated (blacklisted)
Invalid token
Refresh token is invalid or invalidated (blacklisted)
...
```

**15. Регистрирую нового пользователя, отправив POST запрос localhost:8080/api/v1/auth/register с телом:**

```json
{
   "username": "new user",
   "password": "megapassword"
}
```

**Что не реализовано:**

/logout добавляет в blacklist один токен, который приходит в заголовке Authorization. Если это access токен, то он
блокируется, но остается refresh токен 🤷‍♂️.