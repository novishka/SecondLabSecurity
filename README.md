# Password Cracking Tool

Утилита для подбора паролей к хешам с поддержкой SHA-1, MD5, bcrypt и Argon2.

## Установка

```bash
pip install -r requirements.txt
```

## Использование

### Запуск тестов
```bash
python test_all.py
```
Результаты тестов будут выведены в файл `out`.

### Подбор пароля SHA-1
```bash
python simple_main.py sha1 <хеш> --workers 8
```

### Подбор пароля MD5
```bash
python simple_main.py md5 <хеш> --workers 8
```

### Подбор пароля bcrypt
```bash
python simple_main.py bcrypt <хеш> --workers 4
```

### Подбор пароля Argon2
```bash
python simple_main.py argon2 <хеш> --workers 4
```

## Параметры

- `--workers N` - количество рабочих процессов (по умолчанию 4)
- `--timeout S` - таймаут в секундах
- `--charset STRING` - пользовательский набор символов
- `--min-len N` - минимальная длина пароля
- `--max-len N` - максимальная длина пароля

## Примеры

Подбор пароля к SHA-1 хешу "admin":
```bash
python simple_main.py sha1 7c4a8d09ca3762af61e59520943dc26494f8941b --workers 8 --max-len 10
```

Подбор 6-значного числового пароля к MD5:
```bash
python simple_main.py md5 5d41402abc4b2a76b9719d911017c592 --workers 8 --charset "0123456789" --min-len 6 --max-len 6
```
