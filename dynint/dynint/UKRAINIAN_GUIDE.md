# Dynint - Повна інструкція з встановлення та використання для Ubuntu Linux

`dynint` - це інструментарій для аналізу Linux ELF бінарних файлів, що працює в двох режимах:

- `dynmap` — статичний аналізатор для інвентаризації функцій, базових блоків, PLT викликів і динамічних залежностей
- `dyntrace` — динамічний трейсер на основі Frida для інструментування під час виконання

## Системні вимоги

- Linux 18.04+ (рекомендується 20.04+)
- Python 3.9 або вища версія
- Git
- Docker та Docker Compose (для контейнерного встановлення)

##  Встановлення

### Варіант 1: Встановлення через Docker (рекомендується)

#### 1. Встановлення Docker та Docker Compose

```bash
# Оновлення пакетів системи
sudo apt update

# Встановлення Docker
sudo apt install docker.io docker-compose

# Додавання користувача до групи docker
sudo usermod -aG docker $USER

# Перезавантаження або вийдіть/увійдіть в систему
newgrp docker
```

#### 2. Клонування репозиторію

```bash
git clone https://github.com/smander/algebra-system.git
cd dynint
```

#### 3. Збірка та запуск контейнерів

```bash
# Збірка контейнерів
docker compose build

# Запуск контейнерів у фоновому режимі
docker compose up -d
```

### Варіант 2: Локальне встановлення

#### 1. Встановлення системних залежностей

```bash
# Оновлення пакетів системи
sudo apt update

# Встановлення Python 3.9+ та pip
sudo apt install python3.9 python3-pip python3-dev

# Встановлення системних бібліотек для Frida
sudo apt install build-essential libffi-dev
```

#### 2. Встановлення додаткових залежностей (опціонально)

```bash
# Для BCC backend
sudo apt install bcc-tools libbcc-dev

# Для розширеного аналізу
sudo apt install python3-capstone
```

#### 3. Встановлення Python пакетів

```bash
# Клонування репозиторію
git clone https://github.com/smander/algebra-system.git
cd dynint

# Встановлення в режимі розробки
pip3 install -e .

# Або встановлення залежностей вручну
pip3 install pyelftools>=0.30 frida>=16.0.0
```

## Використання

### Режим 1: Статичний аналіз (`dynmap`)

#### Базовий синтаксис
```bash
python -m dynint.cli map <БІНАРНИЙ_ФАЙЛ> [ОПЦІЇ]
```

#### Параметри команди `map`:

| Параметр | Опис | Приклад |
|----------|------|---------|
| `<БІНАРНИЙ_ФАЙЛ>` | Шлях до ELF бінарного файлу (обов'язковий) | `./my_program` |
| `--output, -o` | Шлях для збереження JSON карти (за замовчуванням: "map.json") | `-o analysis.json` |
| `--only-extern-calls` | Включити тільки зовнішні виклики в карту | `--only-extern-calls` |
| `--with-dwarf` | Включити DWARF інформацію про файл:рядок | `--with-dwarf` |
| `--bytes` | Включити байти інструкцій для викликів | `--bytes` |
| `--analysis-level` | Рівень деталізації аналізу ("symbols", "basic-blocks") | `--analysis-level symbols` |

#### Приклади використання:

```bash
# Базовий статичний аналіз
python -m dynint.cli map ./my_program -o map.json

# Розширений аналіз з debug інформацією та байтами
python -m dynint.cli map ./my_program -o map.json --with-dwarf --bytes

# Аналіз тільки PLT викликів
python -m dynint.cli map ./my_program -o map.json --only-extern-calls

# Аналіз на рівні символів
python -m dynint.cli map ./my_program -o map.json --analysis-level symbols
```

#### Використання через Docker:

```bash
# Базовий аналіз
docker compose run --rm dynint-frida python -m dynint.cli map ./my_program -o output/map.json

# Підключення зовнішнього бінарного файлу
docker compose run --rm -v /path/to/програми:/data/binary dynint-frida python -m dynint.cli map /data/binary -o output/map.json
```

### Режим 2: Динамічне трасування (`dyntrace`)

#### Базовий синтаксис
```bash
python -m dynint.cli trace --map <ФАЙЛ_КАРТИ> [ОПЦІЇ_ЦІЛІ] [ОПЦІЇ_ТРАСУВАННЯ]
```

#### Параметри команди `trace`:

**Обов'язкові параметри:**
| Параметр | Опис | Приклад |
|----------|------|---------|
| `--map` | Шлях до попередньо згенерованого map.json файлу | `--map map.json` |

**Вибір цілі (один обов'язковий):**
| Параметр | Опис | Приклад |
|----------|------|---------|
| `--pid` | PID процесу для підключення | `--pid 1234` |
| `--spawn` | Бінарний файл для запуску під інструментуванням | `--spawn ./my_program` |
| `--args` | Аргументи для запущеної програми (останній параметр) | `--args arg1 arg2` |

**Конфігурація трасування:**
| Параметр | Опис | Приклад |
|----------|------|---------|
| `--backend` | Backend для трасування ("frida", "bcc", "dyninst") | `--backend frida` |
| `--lib` | Бібліотека для трасування (можна вказати кілька разів) | `--lib libc.so.6` |
| `--fn` | Конкретна функція для трасування (можна вказати кілька разів) | `--fn malloc --fn free` |
| `--callsite` | Адреси викликів для трасування | `--callsite 0x12345` |

**Вивід та фільтрація:**
| Параметр | Опис | Приклад |
|----------|------|---------|
| `--output` | Записати JSONL трасування у файл замість  | `--output trace.jsonl` |
| `--sample` | Спецификація семплування, наприклад "1/100" | `--sample 1/10` |
| `--since` | Ігнорувати події до цієї мітки часу (секунди) | `--since 1000` |
| `--duration` | Зупинити трасування через вказану кількість секунд | `--duration 30.0` |

#### Приклади використання:

```bash
# Підключення до існуючого процесу
python -m dynint.cli trace --pid 1234 --map map.json --fn malloc --fn free

# Запуск нового процесу
python -m dynint.cli trace --spawn ./my_program --map map.json --fn recv --fn send

# Трасування конкретної бібліотеки
python -m dynint.cli trace --spawn ./my_program --map map.json --lib libc.so.6

# З семплуванням та обмеженням за часом
python -m dynint.cli trace --spawn ./my_program --map map.json --fn malloc --sample 1/10 --duration 30.0

# З виводом у файл
python -m dynint.cli trace --spawn ./my_program --map map.json --fn malloc --output trace.jsonl

# Запуск з аргументами
python -m dynint.cli trace --spawn ./my_program --map map.json --fn main --args --verbose --config config.txt
```

#### Використання через Docker:

```bash
# Базове трасування
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./my_program --map map.json --fn malloc

# З виводом у файл
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./my_program --map map.json --fn malloc --output output/trace.jsonl

# Підключення зовнішніх файлів
docker compose run --rm -v /path/to/програми:/data/binary -v /path/to/map.json:/data/map.json dynint-frida python -m dynint.cli trace --spawn /data/binary --map /data/map.json --fn malloc
```

## Швидкий старт

### Повний приклад роботи:

```bash
# 1. Збірка Docker контейнерів
docker compose build

# 2. Генерація карти статичного аналізу
docker compose run --rm dynint-frida python -m dynint.cli map ./my_program -o output/map.json

# 3. Запуск динамічного трасування
docker compose run --rm dynint-frida python -m dynint.cli trace --spawn ./my_program --map output/map.json --fn malloc --output output/trace.jsonl
```

### Локальне використання:

```bash
# 1. Статичний аналіз
python -m dynint.cli map /usr/bin/ls -o ls_map.json --with-dwarf --bytes

# 2. Динамічне трасування
python -m dynint.cli trace --spawn /usr/bin/ls --map ls_map.json --fn malloc --fn free --args /tmp
```

## Backends для трасування

### Frida (за замовчуванням)
- Найбільш стабільний та функціональний
- Працює в userspace
- Не потребує root привілеїв для більшості операцій


## Робота з зовнішніми файлами

### Монтування зовнішніх бінарних файлів у Docker:

```bash
# Монтування одного файлу
docker compose run --rm -v /path/to/binary:/data/binary dynint-frida python -m dynint.cli map /data/binary -o output/map.json

# Монтування директорії
docker compose run --rm -v /path/to/директорії:/data dynint-frida python -m dynint.cli map /data/binary -o output/map.json

# Монтування карти та бінарного файлу
docker compose run --rm -v /path/to/binary:/data/binary -v /path/to/map.json:/data/map.json dynint-frida python -m dynint.cli trace --spawn /data/binary --map /data/map.json --fn malloc
```
