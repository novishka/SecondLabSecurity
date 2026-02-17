### Запуск

Подбор:

```bash
python -m app.presentation.cli crack --algo md5 --hash e10adc3949ba59abbe56e057f20f883e --charset digits --min-len 1 --max-len 8 --workers 4
```

Бенчмарк скорости (прогон фиксированного числа попыток):

```bash
python -m app.presentation.cli bench --algo sha1 --charset lower --length 6 --attempts 5000000 --workers 4
```

Прогон набора тестов из задания (и сохранение результатов в `./out/`):

```bash
python -m app.presentation.run_lab_benchmarks
```
