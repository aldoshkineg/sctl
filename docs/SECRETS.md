# sctl — архитектура управления секретами (TPM + escrow)

Подробная спецификация для реализации. Локальный, server-less аналог
enterprise secret-manager (Vault-стиль): авто-разблок на «домашней» машине
через TPM + восстановление по мастер-паролю в голове, если железо потеряно.

---

## 1. Принципы (три якоря доверия)

1. **Секреты генерируются случайно** (32+ байт, никем не запоминаются, не
   выводятся из публичного `machine-id`). Источник секрета — randomness, а не
   человеческий пароль.
2. **Повседневный якорь = TPM.** Секрет запечатан (sealed) в чип машины,
   открывается само, без ввода. TPM — аппаратный секрет машины (в отличие от
   несекретного `machine-id`).
3. **Якорь восстановления = мастер-пароль в голове.** Копия каждого секрета
   шифруется под мастер-пароль (age/scrypt) → escrow-блоб вне томов. Если TPM
   умер / сменили железо / переустановка — мастер-пароль восстанавливает доступ.

## 2. Два режима работы и недопустимость рассинхрона

`secret_backend` (глобально) задаёт МЕХАНИЗМ источника секретов:

- **`tpm`** — секреты берутся из TPM-блобов (нуль ввода). Присутствуют И
  escrow-блобы (для восстановления).
- **`escrow`** — TPM нет; секреты берутся расшифровкой escrow-блоба
  мастер-паролем (из файла/env/prompt; файл — только авария).

**Главный риск — рассинхрон** между TPM-блобом и escrow-блобом (они шифруют
одни и те же секреты). Рассинхрон = recovery выдаст устаревший секрет →
невозможность открыть данные.

Правила предотвращения рассинхрона:
- **Единственный writer — `sctl install`.** Он берёт секреты из одного
  in-memory источника и атомарно обновляет ВСЕ представления: seal в TPM +
  запись escrow + (для ключей) смена passphrase на самом ключе. Никаких путей,
  меняющих только одно.
- **`check` как детектор рассинхрона**: одновременно unseal TPM-блобы и
  decrypt escrow (мастер-пароль есть) и СРАВНИВАЕТ карты; несовпадение →
  ошибка «рассинхрон, перезапустите `sctl install`».
- Ротация секрета = повторный `install` (перегенерит и TPM, и escrow).

## 3. Модель секретов — именованная карта

Управляемые секреты хранятся как **карта именованных секретов**
`BTreeMap<String, Zeroizing<Vec<u8>>>`, ключ — составной:

```
gocryptfs:__shared__          -> G   (общий ключ ВСЕХ томов)
gpg:<home_id>:<fingerprint>   -> P   (passphrase мастер-ключа gpg, per-key)
ssh:<abspath_ключа>           -> S   (passphrase ssh-ключа, future, per-key)
```

- **G (gocryptfs)** — ОДИН общий ключ на все тома (текущая модель `keyfile`).
  Не per-volume. Источник = байты существующего `~/.config/sctl/key`.
- **P (gpg)** — единица управления = **конкретный первичный (мастер-)ключ
  по fingerprint** внутри home. В одном home может быть много первичных ключей,
  у каждого — свой passphrase (`gpg --change-passphrase <KEYID>` работает на
  конкретный ключ). Подключи (sub) принадлежат первичному и делят его
  passphrase → пресетим passphrase первичного по всем его keygrip'ам.
  `home_id` = имя sctl-секрета (gpg home = mountpoint секрета).
- **S (ssh, future)** — каждый ssh-ключ (`~/.ssh/...`) имеет свой passphrase;
  карта по абсолютному пути ключа.

Эскроу = ОДИН файл с этой картой (расшифровали целиком → всё в памяти →
берём нужную запись). TPM = по отдельному блобу на каждую запись (ключённую
по id); ансилим только запрошенные.

## 4. Формат escrow-файла

- Контейнер: **age** (scrypt-recipient под мастер-пароль).
  Зависимость: крейт `age` (чистый Rust, без внешних бинарей).
- Plaintext внутри: **TOML** (сериализуем `SecretMap` через `toml`, уже есть в
  зависимостях). Рекомендуется TOML (читаемо, отлаживаемо).
- Пример структуры (до шифрования):
  ```toml
  [secrets."gocryptfs:__shared__"]
  data = "<base64 random bytes>"
  [secrets."gpg:gpg:47298374912873c"]
  data = "<base64 random bytes>"
  [secrets."ssh:/home/u/.ssh/id_ed25519"]
  data = "<base64 random bytes>"
  ```
- `master_passphrase_file` / env `SCTL_MASTER_PASS` / интерактивный промпт
  (`rpassword`) — источник мастер-пароля. Файл — только аварийный путь.

## 5. TPM-блобы

- Хранилище: `state_dir/tpm/<id>.priv` + `<id>.pub` (рядом с прочим state
  sctl), **вне зашифрованных томов**.
- Создание (seal), проверено на машине (tpm2-tools 5.7, tpm2-tss 4.1.3):
  ```
  tpm2_createprimary -C o -c prim.ctx
  echo -n "$SECRET" | tpm2_create -C prim.ctx -i- -u <id>.pub -r <id>.priv -c <id>.ctx
  ```
- Вскрытие (unseal): первичный ключ ВОССОЗДАЁТСЯ каждый раз (детерминирован
  для owner-иерархии с пустым auth + фикс. шаблон), затем
  `tpm2_load` + `tpm2_unseal -c <id>.ctx`. NV-persistence не нужна.
  ```
  tpm2_createprimary -C o -c prim.ctx
  tpm2_load -C prim.ctx -u <id>.pub -r <id>.priv -c <id>.ctx
  tpm2_unseal -c <id>.ctx -o out.bin
  ```
- **PCR (hardened, опц.)**: `tpm2_createpolicy --policy-pcr -l sha256:7`,
  `tpm2_create -L <policy>`; unseal через policy-сессию. Default — БЕЗ PCR
  (блоб переживает обновления прошивки, не привязан к состоянию загрузки).
  Поле `tpm_pcr` (глобальное) включает PCR-политику.
- Доступ: устройства `/dev/tpmrm0`,`/dev/tpm0` группы `tss` (0660); юзер должен
  быть в группе `tss` (после добавления — re-login). Без root не нужно.

## 6. Конфигурация

`config.example.toml`:
```toml
[settings]
default_idle = "15m"
enc_root = "~/.encrypted"
secret_backend         = "tpm"        # "tpm" | "escrow" | (не задан = legacy)
escrow_file            = "~/.config/sctl/sctl-escrow.age"
master_passphrase_file = "~/.config/sctl/master.pass"   # только авария
tpm_pcr                = false         # optional hardened PCR 7

[secrets.gpg]
path = ".gnupg"
gpg = true
gpg_preset = true
tpm_gpg = true          # P этого home управляется через backend; без него — ручной ввод

[secrets.mail]
path = ".local/share/mail"
depends = ["gpg"]
```

Поля:
- `secret_backend` — глобальный механизм. Не задан → **legacy**: gocryptfs
  через plaintext-`keyfile`, gpg — ручной ввод (`.common-seed` больше нет).
- `tpm_gpg` (per-secret opt-in) — управлять passphrase gpg-ключей этого home
  через backend. Без него gpg не обрабатывается автоматически (ручной ввод).
- `escrow_file`, `master_passphrase_file` — пути (expanded_tilde).
- Удаляемые поля/код: `gpg_passphrase_file`, `extract_secret` в `gpg.rs`.
- `tpm_ssh` — будущий per-key opt-in для ssh (аналог `tpm_gpg`).

## 7. Команды

### 7.1 `sctl install [names] [--interactive]`
Единственный writer. Атомарно: seal в TPM + запись escrow + смена passphrase.

Поведение:
- **config-driven (по умолчанию, headless-дружественно)**: энроллит все
  секреты с `tpm_gpg` (и gocryptfs G) без интерактива. G берётся из существующего
  keyfile. gpg — ВСЕ секретные ключи home'а (перечислены ниже) энроллятся.
- **`--interactive`**: перечисляет доступные ключи и даёт выбрать/мультивыбор.

Поток (внутри, для каждого managed-секрета; тома монтируются в порядке deps,
gpg — первым):
```
gpg (home = mountpoint секрета):
  gpg --list-secret-keys --with-colons   # собрать fingerprint первичных ключей
  [interactive] показать (fpr + uid), пользователь выбирает
  для каждого выбранного ключа:
    prompt "текущий пароль"  (rpassword; нужен для смены)
    new = random_secret(32)
    GNUPGHOME=<mnt> gpg --change-passphrase <KEYID>   # old -> new (ключ не меняется)
    map["gpg:<home_id>:<fpr>"] = new

ssh (future, home = ~/.ssh):
  перечислить ВСЕ не-hidden файлы в ~/.ssh, отсечь *.pub
  [interactive] выбор ключей
  для каждого: prompt старый пароль -> new=random -> ssh-keygen -p -P old -N new -f <key>
  map["ssh:<abspath>"] = new

gocryptfs (всегда, если backend задан):
  G = bytes(~/.config/sctl/key)   # adopt, без ре-инита томов
  map["gocryptfs:__shared__"] = G
```
Финализация (атомарно):
```
если backend == "tpm":  для каждой записи map -> tpm::seal(value, id)
эскроу: blob = escrow::seal(map, master); пишем во временный файл -> rename(escrow_file)
```
Промпты install: текущий пароль ключа (для смены) + мастер-пароль (для шифра
эскроу). На экран при install — только краткое подтверждение; полные секреты —
через `recovery`.

### 7.2 `sctl recovery`
Мастер-пароль (prompt/file/env) → `escrow::open(escrow_file)` → **печать ВСЕЙ
карты** (kind:id -> secret) в stdout. TPM-независимо, работает на машине без
TPM. Опц. фильтр по префиксу (напр. только `gpg:`). Предупреждение о том, что
секреты выводятся на экран.

Типичный сценарий миграции: `recovery` → скопировать/ввести пароли → либо
ручной mount, либо `install` на новой машине ребиндит те же секреты в её TPM.

### 7.3 `sctl check` (расширить существующий)
- backend == "tpm": наличие `tpm2-tools` (which), `/dev/tpmrm0`, юзер в `tss`;
  для каждого managed-секрета — наличие TPM-блоба.
- backend == "escrow": наличие `escrow_file`; доступность мастер-пароля
  (файл/env/prompt); **self-test** — decrypt эскроу мастер-паролем (успех/неудача).
- **DESYNC-детектор**: если есть И TPM-блобы, И escrow — unseal все TPM + decrypt
  escrow, сравнить карты; несовпадение → ошибка, требующая `sctl install`.

### 7.4 `sctl mount` (интеграция, без новой команды)
Существующий поток, но с подменой источника:
- gocryptfs: если `secret_backend` задан →
  `pass = secret::resolve_secret("gocryptfs","__shared__")` → пишем во временный
  `0600` passfile (`passfile.rs`) → кормим gocryptfs. Иначе legacy keyfile.
- gpg preset (`gpg.rs`): если `backend` задан && `secret.tpm_gpg` → для каждого
  энролленного ключа home'а `resolve_secret("gpg", "<home_id>:<fpr>")` → preset
  через `gpg-preset-passphrase` по ВСЕМ keygrip'ам этого ключа (включая sub).
  Иначе — ручной ввод (ничего не делаем).

## 8. Модульная структура (новые/изменённые файлы)

- `src/rand.rs` — `random_secret(len: usize) -> Zeroizing<Vec<u8>>` (через
  `rand`/`getrandom`).
- `src/escrow.rs`:
  - `seal(map: &SecretMap, master: &Zeroizing<String>) -> Result<Vec<u8>>`
    (age-scrypt, возвращает зашифрованные байты).
  - `open(blob: &[u8], master: &Zeroizing<String>) -> Result<SecretMap>`.
- `src/tpm.rs`:
  - `seal(secret: &[u8], id: &str, pcr: bool) -> Result<()>` (пишет
    `state_dir/tpm/<id>.{priv,pub}`).
  - `unseal(id: &str) -> Result<Zeroizing<Vec<u8>>>`.
  - shell-out к `tpm2_*`, использует временный `prim.ctx`.
- `src/secret.rs` (новый) — единый `resolve_secret(kind, id) -> Result<Zeroizing<Vec<u8>>>`:
  - backend=="tpm" → `tpm::unseal(id)`;
  - backend=="escrow" → lazy-decrypt `escrow_file` (кэш карты в сессии) →
    взять запись `format!("{kind}:{id}")`.
  - `SecretMap = BTreeMap<String, Zeroizing<Vec<u8>>>`.
- `src/install.rs` — описанный в §7.1 поток.
- `src/recovery.rs` — §7.2.
- `cli.rs` — добавить `Install { names, interactive }`, `Recovery { filter }`;
  убрать упоминание backup.
- `config.rs` — поля `secret_backend`, `tpm_gpg`, `tpm_ssh` (future),
  `escrow_file`, `master_passphrase_file`, `tpm_pcr`; убрать `gpg_passphrase_file`.
- `gpg.rs` — удалить `extract_secret` и логику `.common-seed`; `preset` через
  `secret::resolve_secret` при `tpm_gpg`.
- `mount.rs` — gocryptfs-ключ через `secret::resolve_secret`.
- `check.rs` — §7.3.

## 9. Свойства безопасности

- На диске — только ciphertext (TPM-блобы + escrow под мастер-паролем).
  Plaintext-keyfile из конфиг-дира убирается (реальное улучшение).
- Украденный диск бесполезен: TPM-блобы не откроются вне чипа, escrow требует
  мастер-пароль.
- **Смена passphrase ≠ смена ключа**: `gpg --change-passphrase` / `ssh-keygen -p`
  только пере-заворачивают существующий ключ; fingerprint/keygrip/подписи
  неизменны. Ротация управляемого секрета — дёшево, без боли.
- Все секреты в памяти — `Zeroizing` (zeroize-on-drop). Мастер-файл — 0600,
  только авария; в штатном tpm-режиме ежедневно не нужен.
- Локальный процесс на машине может ансилить (как и читать смонтированный том) —
  приемлемо (угроза «внутри периметра»).
- SSH покрыт бесплатно, если ssh через gpg-agent (текущая схема). Отдельный
  `tpm_ssh` — future для standalone ssh-ключей.

## 10. Проверено на текущей машине

- TPM: **fTPM 2.0** (`/sys/class/tpm/tpm0/tpm_version_major=2`, MSFT0101),
  PCR-банки sha1+sha256. `tpm2-tools` (5.7) + `tpm2-tss` (4.1.3) установлены
  через `emerge`.
- Устройства `/dev/tpmrm0`,`/dev/tpm0` — группа `tss`, mode 0660 (udp-правило
  `60-tpm-udev.rules`). Юзер `hash` добавлен в `tss`.
- **Seal/unseal работает БЕЗ root** через группу `tss` (нужен re-login текущей
  сессии, чтобы группа применилась; либо `sg tss -c ...`).
- Полный roundtrip `createprimary → create(seal) → unseal` проверен вручную,
  значение восстанавливается корректно.

## 11. Открытые решения / допущения (требуют визы)

1. **G = байты существующего keyfile**, подаются gocryptfs как passphrase через
   временный passfile (adopt, тома НЕ ре-инициализируются). Если нужна генерация
   свежего ключа + re-init — отдельная future-опция.
2. **Escrow plaintext = TOML** (а не bincode) ради читаемости.
3. **TPM: первичный ключ воссоздаётся каждый раз** (без NV-persistence).
4. **config-driven install энроллит ВСЕ ключи** home'а с `tpm_gpg` (без
   поштучного выбора); выбор конкретных ключей — только в `--interactive`.
5. **PCR выключен по умолчанию** (`tpm_pcr=false`); включение = привязка к
   secure-boot (PCR 7), ломается при обновлении прошивки.
6. `sctl install` в режиме `escrow` **устанавливает мастер-пароль** (он нужен
   для шифра эскроу); режим `tpm` — тоже просит мастер-пароль один раз (для
   записи escrow), далее ежедневно не нужен.

> **Статус допущений:** все 6 пунктов выше **визированы** (согласованы с
> пользователем в сеанс проектирования).

### 11.1. Решения по итогам обсуждения реализации

- **TPM — предпочтительно Rust-биндинг `tss-esapi`** (линкуется к системному
  `tpm2-tss`, уже установлен: 4.1.3). Если сборка/линковка окажется слишком
  сложной — **fallback на `tpm2-tools` CLI** (отмечен как системная
  зависимость, см. §12). Итоговый выбор фиксируется при реализации шага 4.
  В обоих случаях интерфейс `tpm.rs` (`seal`/`unseal`) остаётся неизменным,
  чтобы `secret.rs`/`install.rs` не зависели от выбора реализации.
- **Интерактивный выбор ключей — кастомный номерной пикер без зависимостей**
  (в духе существующего `rpassword`-промпта): печать пронумерованного списка
  + парсинг multi-select (`1,3-5`). Гейт на `IsTerminal`; без TTY `--interactive`
  завершается ошибкой. Альтернатива `dialoguer` отклонена (лишняя зависимость
  ради одного промпта).
- **Список gpg-ключей — через `gpg` CLI** (`--list-secret-keys --with-colons
   --with-keygrip`, уже реализовано в `gpg.rs::keygrips`). Чистый Rust-OpenPGP
   (`sequoia`/`pgp`) не годится как первичный источник — он не управляет живым
   gpg-agent, а мутации (`--change-passphrase`, `--quick-add-key`,
   `gpg-preset-passphrase`) всё равно через CLI.

### 11.2. Отклонение: ротация gpg passphrase отложена

Спецификация (§2, §11.6) предполагала, что `sctl install` **меняет passphrase
gpg-ключа на случайный P**, известный только sctl. На gpg 2.5.20 это **не
работает** неинтерактивно:

- `--quick-passwd` отсутствует.
- `--change-passphrase` с `--pinentry-mode=loopback` использует ОДИН и тот же
  passphrase для обоих промптов (old и new) — новый passphrase не применяется,
  старый продолжает открывать ключ. Проверено: export под новым → FAIL, под
  старым → OK.
- export(old) → delete → import(new через `--passphrase`, old через `--passphrase-fd`)
  тоже не меняет passphrase ключа (老д остаётся рабочим).

Поэтому `install` **сохраняет существующий passphrase** (промпт old → seal в
TPM/escrow → preset в gpg-agent). Секрет по-прежнему запечатан в бэкенде и
авто-разблокируется; отложена только «рандомизация» самого passphrase ключа.
Решение при необходимости: кастомный `pinentry`-wrapper, возвращающий разные
значения для old/new, либо интерактивный `gpg --change-passphrase` в TTY-режиме.
Зафиксировано в `src/install.rs` (док-comment у `build_map`).

## 12. Зависимости

| Что | Тип | Источник | Примечание |
|-----|-----|----------|------------|
| `age` | Rust-крейт | crates.io | шифр escrow (scrypt-recipient) |
| `secrecy` | Rust-крейт | crates.io | `Secret<String>` для мастер-пароля |
| `base64` | Rust-крейт | crates.io | кодирование секретов в TOML |
| `rand` | Rust-крейт | crates.io | `random_secret` |
| `zeroize` | Rust-крейт | уже есть | `Zeroizing` |
| `toml`, `serde` | Rust-крейт | уже есть | сериализация карты |
| `tss-esapi` | Rust-крейт | crates.io | **TPM** (линк к системному tpm2-tss) |
| `gpg` | системная утилита | `app-crypt/gnupg` | листинг + мутации ключей (§11.1) |
| `tpm2-tools` | системная утилита | `app-crypt/tpm2-tools` | **fallback TPM**, если `tss-esapi` не соберётся |
| `ssh-keygen` | системная утилита | `net-misc/openssh` | генерация/ротация ssh-ключей (future) |
| `tpm2-tss` | системная библиотека | `app-crypt/tpm2-tss` 4.1.3 | нативная линковка для `tss-esapi` |

Все системные утилиты уже присутствуют на целевой машине (Gentoo).

## 13. TODO — задачи реализации

- [x] **A. Спецификация** — `docs/SECRETS.md` написана и визирована.
- [x] **B. Проверка TPM** на машине (fTPM 2.0, round-trip seal/unseal).
- [x] **C. Зависимости** добавлены в `Cargo.toml` (`age`, `secrecy`, `rand`,
        `base64`); решение `tss-esapi` vs `tpm2-tools` зафиксировано в §12.
- [x] **1. `config.rs`** — поля `secret_backend`(enum), `escrow_file`,
        `master_passphrase_file`, `tpm_pcr`; per-secret `tpm_gpg`. Учтены
        конструкторы в `deps.rs`/тестах.
- [x] **2. `src/rand.rs`** — `random_secret` (написан, подключён в `main.rs`).
- [x] **3. `src/escrow.rs`** — `SecretMap`, `seal`/`open` (age 0.11.3 scrypt +
        TOML). Round-trip тесты **проходят** (`cargo test --bin sctl escrow`).
- [x] **4. `src/tpm.rs`** — `seal`/`unseal` через `tpm2-tools` (shell-out;
        пути `<state_dir>/tpm/<id>.{priv,pub}`; интерфейс уже под `tss-esapi`).
        **БЕЗ skip/guard-костылей** — тест `seal_unseal_roundtrip` реально
        ходит в TPM и требует активной группы `tss` (после перезагрузки).
        PCR-путь пока `bail!` (не реализован, см. §5).
- [x] **5. `src/secret.rs`** — `resolve_secret(kind,id)` (Tpm→unseal; Escrow→
        lazy-decrypt с кэшем `OnceLock`; мастер-пароль env>`master_passphrase_file`>prompt).
        Тесты `escrow_resolve` + `tpm_resolve` **проходят**.
- [x] **11. Тесты (фикстура)** — `tests/common/mod.rs` (N gpg-мастеров с
        сабключами sign+auth; ssh rsa/ecdsa/ed25519) + `tests/keys_fixture.rs`.
        **Проходят** (`cargo test --test keys_fixture`): 2 мастера с sign+auth
        подключами; ssh rsa/ecdsa/ed25519 с верификацией пароля.
- [x] **4. `src/tpm.rs`** — `seal`/`unseal` через `tpm2-tools` (shell-out);
         пути `<state_dir>/tpm/<id>.{priv,pub}` (реализовано; дубликат-черновик
         выше закрыт). `tss-esapi`-своп — отдельная опциональная задача (§12).
- [x] **5. `src/secret.rs`** — `resolve_secret(kind,id)` реализован (дубликат-черновик
         выше закрыт).
- [x] **6. `src/install.rs`** + `cli.rs`(`Install{names,interactive}`) +
         `main.rs` — единственный writer: `build_map` (G из keyfile + gpg-пассфразы
         `tpm_gpg`-секретов) → `finalize` (seal TPM + атомарная запись escrow).
         Тесты `finalize_then_recovery_roundtrip_{escrow,tpm}` **проходят** (TPM
         реально). Алиас `inst` (чтобы не конфликтовать с `init`=`in`).
- [x] **7. `src/recovery.rs`** + `cli.rs`(`Recovery{filter}`) — `read_map` +
         печать карты (base64). Тесты выше покрывают round-trip.
- [x] **8. `gpg.rs`** — удалены `extract_secret`/`.common-seed`/`gpg_passphrase_file`;
         `preset` через `secret::resolve_secret` при `backend+tpm_gpg` (fpr→keygrips
         рантаймом через `keys_with_keygrips`). Legacy/manual → no-op (ручной ввод).
- [x] **9. `mount.rs`** — G через `resolve_secret` (+`passfile::from_bytes`);
         в backend-режиме прямое чтение keyfile не используется для монтирования.
- [x] **10. `check.rs`** — backend-проверки (tpm2-tools/`/dev/tpmrm0`/`tss`;
         escrow self-test) + **desync-детектор** (unseal TPM vs decrypt escrow).
- [x] **11. Тесты (фикстура)** — `tests/common/mod.rs` (N gpg-мастеров с
         сабключами sign+auth; ssh rsa/ecdsa/ed25519) + `tests/keys_fixture.rs`.
         **Проходят** (`cargo test --test keys_fixture`).
- [x] **12. Тесты (поведенческие)** — `src/lib.rs` + `tests/backend.rs`:
         фикстура → `install` (`build_map`+`finalize`) → `recovery::read_map` и
         `secret::resolve_secret` возвращают те же P; TPM-вариант проверяет
         отсутствие desync. **Проходят**.
- [x] **13. `README.md`** — раздел «Secret backend (TPM + escrow)» + `install`/
         `recovery`/`check`; gpg-preset обновлён под backend-режим.

---

## 14. Статус реализации (snapshot: 2026-07-12, обновлено)

**Вердикт: реализация завершена** (TODO §13 — все пункты `[x]`). Ежедневный путь
(mount/gpg/check) подключён к бэкенду; изолированные и поведенческие тесты
проходят, включая реальный TPM.

### Готово и рабочее (проверено)
- Инфраструктура бэкенда: `config`, `escrow` (age scrypt + TOML), `tpm`
  (реальный fTPM 2.0 через `tpm2-tools`), `secret` (`resolve_secret` +
  `OnceLock`-кэш мастер-пароля), `rand` (`random_secret` + тест).
- Команды `install` (alias `inst`) / `recovery` (alias `rc`): единственный
  writer — `build_map` → `finalize` (seal TPM + атомарный escrow). Юнит-тесты
  round-trip зелёные, TPM-тест реально ходит в чип.
- **Шаг 8:** `gpg.rs::preset` через `secret::resolve_secret` при
  `backend+tpm_gpg` (fpr→keygrips через `keys_with_keygrips`); `.common-seed`/
  `extract_secret`/`gpg_passphrase_file` удалены.
- **Шаг 9:** `mount.rs` берёт `G` из `resolve_secret` (+`passfile::from_bytes`);
  legacy-режим — через `keyfile`.
- **Шаг 10:** `check.rs` — backend-проверки (tpm2-tools/`/dev/tpmrm0`/`tss`;
  per-secret TPM-блобы; escrow self-test) + **desync-детектор** (симметричный,
  TPM→escrow: ловит расхождение значений И TPM-блобы без эскроу-контрчасти).
  `check` не блокируется на интерактивном вводе мастер-пароля (non-interactive
  резолвер).
- **Шаг 12:** `src/lib.rs` + `tests/backend.rs` — фикстура gpg → `install`
  (`build_map`+`finalize`) → `recovery::read_map`/`resolve_secret` возвращают
  те же P; TPM-вариант проверяет отсутствие desync.
- **Шаг 13:** README — раздел «Secret backend (TPM + escrow)» + `install`/
  `recovery`/`check`; gpg-preset обновлён.
- Фикстуры `tests/common/mod.rs` + `tests/keys_fixture.rs` — проходят.
- **Итого: 37 тестов зелёных** (20 unit + 13 CLI-integration + 2 fixture +
  2 behavioral).

### Отложено (документировано, не блокирует)
- **§11.2 Ротация gpg passphrase** — gpg 2.5.20 не меняет passphrase на *другой*
  неинтерактивно; `install` хранит существующий пароль (пресет работает).
- **§11.4 Интерактивный номерной пикер** — `InstallOpts.interactive` пока не
  задействован; config-driven энроллит все ключи home'а (решение №4).
- **`tss-esapi`** — выбран fallback `tpm2-tools` (§11.1); своп — опционально.
- **PCR-политика** — `tpm_pcr=true` блокируется явной ошибкой (§5), не реализовано.
- **SSH (`tpm_ssh`)** — future, отдельный opt-in (§6/§9).
