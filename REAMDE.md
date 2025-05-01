1. При запуске TestUserLoader добавляет тестовых юзеров
2. Иду в Postman, POST запрос localhost:8080/api/v1/auth/login с телом:

   {
   "username": "user",
   "password": "password"
   }

3. Получаю токен, отправляю GET запрос localhost:8080/api/v1/hello с заголовком:

   Authorization: Bearer <полученный ранее токен>
4. Получаю в ответ 200 OK
5. Радуюсь