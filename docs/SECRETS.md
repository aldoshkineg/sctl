# sctl — архитектура управления секретами (TPM + escrow)

Подробная спецификация для реализации. Локальный, server-less аналог
enterprise secret-manager (Vault-стиль): авто-разблок на «домашней» машине
через TPM + восстановление по мастер-паролю в голове, если железо потеряно.

> **⚠️ Актуальная архитектура — см. §17 (DEK-модель, v0.8.5).** Разделы §1–§13 —
> исходная проектная спецификация. В ходе реализации модель хранения изменилась:
> вместо отдельного TPM-блоба на каждый секрет теперь **один** запечатанный в
> TPM ключ шифрования данных (DEK) + **один** зашифрованным им файл-карта того же
> формата, что и escrow. §17 описывает итоговое поведение и имеет приоритет над
> описаниями «per-key блобов» в §3/§5/§7/§8.

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

`secret_backend` (глобально, ОБЯЗАТЕЛЬНО) задаёт МЕХАНИЗМ источника секретов:

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

- **G (gocryptfs)** — ОДИН общий ключ на все тома. Не per-volume. Источник =
  gocryptfs-пароль, запрошенный при `sctl install` (или env `CRYPT_PASS` для
  автоматизации); хранится ТОЛЬКО в бэкенде, plaintext-keyfile на диске нет.
- **P (gpg)** — единица управления = **конкретный первичный (мастер-)ключ
  по fingerprint** внутри home. В одном home может быть много первичных ключей,
  у каждого — свой passphrase (`gpg --change-passphrase <KEYID>` работает на
  конкретный ключ). Подключи (sub) принадлежат первичному и делят его
  passphrase → пресетим passphrase первичного по всем его keygrip'ам.
  `home_id` = имя sctl-секрета (gpg home = mountpoint секрета).
- **S (ssh, future)** — каждый ssh-ключ (`~/.ssh/...`) имеет свой passphrase;
  карта по абсолютному пути ключа.

Эскроу = ОДИН файл с этой картой (расшифровали целиком → всё в памяти →
берём нужную запись). TPM (v0.8.5) — тоже ОДИН файл того же формата, но
обёрнутый случайным DEK, который запечатан в TPM: один `tpm2_unseal` достаёт
DEK → расшифровываем весь файл-карту → всё в памяти. См. §17. (Исходно
планировалось по TPM-блобу на каждую запись — заменено DEK-моделью из-за лимита
TPM на размер sealed-данных ≈128 байт.)

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

## 5. TPM: sealed DEK + файл-карта (v0.8.5)

> Историческое замечание: исходно планировалось `state_dir/tpm/<id>.{priv,pub}`
> на каждый секрет. Заменено DEK-моделью — TPM не может запечатать больше ≈128
> байт (проверено: 128 OK, 256 FAIL), а полная карта больше. Актуально — §17.

- **Хранилище (вне зашифрованных томов):**
  - `state_dir/tpm/dek.priv` + `dek.pub` — DEK (32 случайных байта), запечатанный
    в TPM. Единственный sealed-объект. Имена непрозрачны: fingerprint'ов/имён
    ключей на диске нет.
  - `state_dir/tpm/map.age` — вся карта секретов, зашифрованная DEK; тот же
    age-контейнер, что и escrow (§4), только «пароль» = DEK, а не мастер-пароль.
  - `$XDG_RUNTIME_DIR/sctl/prim-<hash>.ctx` (fallback `<tmp>/sctl-<uid>/`) —
    кэш контекста первичного ключа (не секрет). Живёт в per-boot tmpfs, **не** в
    `state_dir`: сохранённый TPM-контекст зашифрован context-ключом, который TPM
    регенерирует при каждом сбросе, поэтому файл валиден лишь в пределах одной
    загрузки и всё равно пересоздаётся на первом mount после ребута. `<hash>` —
    от `state_dir`, чтобы разные конфиги/параллельные тесты не сталкивались.
- **Создание (seal), tpm2-tools 5.7 / tpm2-tss 4.1.3:**
  ```
  tpm2_createprimary -C o -c prim.ctx           # один раз, кэшируется
  echo -n "$DEK" | tpm2_create -C prim.ctx -i- -u dek.pub -r dek.priv
  ```
- **Вскрытие (unseal):**
  ```
  tpm2_load -C prim.ctx -u dek.pub -r dek.priv -c dek.ctx
  tpm2_unseal -c dek.ctx            # → DEK; далее age-decrypt map.age под DEK
  ```
  Первичный ключ детерминирован (owner-иерархия), его контекст кэшируется в
  `prim-<hash>.ctx` (per-boot tmpfs, §выше). Если `tpm2_load` падает (TPM очищен
  `tpm2_clear` → context устарел) — контекст пересоздаётся автоматически и load
  повторяется.
- **PCR (hardened, опц.)**: `tpm_pcr=true` — пока `bail!` (не реализовано, §5
  исходной спецификации). Default — без PCR.
- **Права:** `dek.priv`/`dek.pub`/`map.age` (`state_dir/tpm/`) и `prim-*.ctx`
  (runtime) — `chmod 0600` независимо от umask.
- **Доступ:** `/dev/tpmrm0`,`/dev/tpm0` группы `tss` (0660); юзер в `tss`
  (после добавления — re-login). Root не нужен.

## 6. Конфигурация

`config.example.toml`:
```toml
[settings]
default_idle = "15m"
enc_root = "~/.encrypted"
secret_backend         = "tpm"        # ОБЯЗАТЕЛЬНО: "tpm" | "escrow"
escrow_file            = "~/.config/sctl/sctl-escrow.age"
master_passphrase_file = "~/.config/sctl/master.pass"   # только авария
tpm_pcr                = false         # optional hardened PCR 7

[secrets.gpg]
path = ".gnupg"
gpg = true
gpg_preset = true       # passphrases этого home управляются через backend (TPM или
                      # escrow — по secret_backend); без gpg_preset — ручной ввод

[secrets.mail]
path = ".local/share/mail"
depends = ["gpg"]
```

Поля:
- `secret_backend` — глобальный механизм, ОБЯЗАТЕЛЕН (`tpm` | `escrow`); если не
  задан — `sctl` завершается с ошибкой конфигурации.
- `gpg_preset` (per-secret opt-in) — управлять passphrase gpg-ключей этого home
  через backend; механизм (tpm/escrow) выбирается `secret_backend`. Без
  `gpg_preset` этот home не обрабатывается автоматически (gpg спрашивает сам).
- `escrow_file`, `master_passphrase_file` — пути (expanded_tilde).
- Удалённые поля/код: `keyfile`, `gpg_passphrase_file`, `extract_secret`,
  `tpm_gpg` (слит с `gpg_preset`), env `SCTL_KEYFILE`/`SCTL_KEY`. Легаси-режим
  без `secret_backend` удалён.
- `tpm_ssh` — будущий per-key opt-in для ssh (аналог `gpg_preset`).

## 7. Команды

### 7.1 `sctl install [names]`
Единственный writer. Атомарно: seal в TPM + запись escrow.

Поведение:
- **config-driven (headless-дружественно)**: энроллит все секреты с `gpg_preset`
  (и gocryptfs G). G берётся из промпта gocryptfs-пароля (с подтверждением) или
  env `CRYPT_PASS`. gpg — ВСЕ секретные ключи home'а (перечислены ниже) энроллятся
  (для каждого спрашивается passphrase; пустой ввод = пропустить ключ).

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
Финализация (`finalize`, атомарно — tmp + rename, `0600`):
```
эскроу (всегда): blob = escrow::seal(map, master) -> escrow_file
если backend == "tpm":
    DEK = random(32)
    tpm::seal_dek(DEK)                       # -> dek.priv/dek.pub
    tpm_blob = escrow::seal(map, base64(DEK))  # тот же формат, «пароль»=DEK
    write -> state_dir/tpm/map.age
```
Промпты install: пароль каждого gpg-ключа (проверяется на месте, см. ниже) +
мастер-пароль (для escrow). На экран — только краткое подтверждение; полные
секреты — через `recovery`.

**Проверка пароля gpg на месте (v0.8.1+):** введённый пароль немедленно
проверяется — кэшируется через `gpg-preset-passphrase` и затем `gpg
--export-secret-keys <fpr>` вынуждает агент расшифровать ключ; неверный пароль →
повтор запроса. (`--preset` сам по себе НЕ проверяет пароль, только кэширует.)

**Пропуск ключа (v0.8.5):** на промпте пароля gpg-ключа **пустой Enter пропускает
ключ** — он не попадает в бэкенд (не энроллится, не пресетится; gpg спросит его
пароль вручную по необходимости). Имена пропускаемых ключей в конфиге НЕ хранятся
(идея `gpg_skip_keys` отклонена как «имена ключей в конфиге»). Ctrl+S не
используется — это XOFF терминала.

### 7.2 `sctl recovery`
Мастер-пароль (prompt/file/env) → `escrow::open(escrow_file)` → **печать ВСЕЙ
карты** (kind:id -> secret) в stdout. TPM-независимо, работает на машине без
TPM. Опц. фильтр по префиксу (напр. только `gpg:`). Предупреждение о том, что
секреты выводятся на экран.

Типичный сценарий миграции: `recovery` → скопировать/ввести пароли → либо
ручной mount, либо `install` на новой машине ребиндит те же секреты в её TPM.

### 7.3 `sctl check` (расширить существующий)
- backend == "tpm": наличие `tpm2-tools` (which), `/dev/tpmrm0`, юзер в `tss`;
  наличие `dek.priv` (sealed DEK) и `map.age`; права `map.age` (`0600`).
- backend == "escrow": наличие `escrow_file`; доступность мастер-пароля
  (файл/env/prompt); **self-test** — decrypt эскроу мастер-паролем (успех/неудача).
- **DESYNC-детектор (v0.8.5)**: если есть И TPM, И escrow — расшифровать ОБЕ
  полные карты (TPM через DEK, escrow через мастер-пароль) и сравнить ключ-в-ключ:
  расхождение значения / запись только в одной карте → ошибка `sctl install`.
  Пропущенные при install ключи просто отсутствуют в обеих картах — не ложно-
  срабатывают. `check` не блокируется на интерактивном вводе мастер-пароля.

### 7.4 `sctl mount` (интеграция, без новой команды)
Существующий поток, но с подменой источника:
- gocryptfs: `pass = secret::resolve_secret("gocryptfs","__shared__")` (для TPM —
  один unseal DEK + decrypt `map.age`, кэш карты на процесс) → временный `0600`
  passfile → gocryptfs.
  - **Окно миграции:** если бэкенд ещё не заенроллен (`backend_missing`: нет
    `dek.priv`/`map.age` или escrow-файла) — `mount`/`init` спрашивают
    gocryptfs-пароль (или env `CRYPT_PASS`) с предупреждением, чтобы можно было
    примонтировать gpg-том ДО первого `install`. Реальная ошибка unseal на
    *заенролленном* бэкенде пробрасывается, отката нет.
- gpg preset (`gpg.rs`): если `secret.gpg_preset` → один раз берём всю карту
  (`resolve_all`), для каждого ключа home'а, который ЕСТЬ в карте, делаем preset
  через `gpg-preset-passphrase` по всем keygrip'ам (вкл. sub). Ключи,
  пропущенные при install, отсутствуют в карте → тихо пропускаются.

## 8. Модульная структура (новые/изменённые файлы)

- `src/rand.rs` — `random_secret(len: usize) -> Zeroizing<Vec<u8>>` (через
  `rand`/`getrandom`).
- `src/escrow.rs`:
  - `seal(map: &SecretMap, master: &Zeroizing<String>) -> Result<Vec<u8>>`
    (age-scrypt, возвращает зашифрованные байты).
  - `open(blob: &[u8], master: &Zeroizing<String>) -> Result<SecretMap>`.
- `src/tpm.rs` (v0.8.5, DEK-модель):
  - `seal_dek(dek: &[u8], cfg) -> Result<()>` (пишет `state_dir/tpm/dek.{priv,pub}`).
  - `unseal_dek(cfg) -> Result<Zeroizing<Vec<u8>>>` (кэш по пути `dek.priv`).
  - `dek_exists(cfg) -> bool`.
  - shell-out к `tpm2_*`; primary-контекст кэшируется в runtime tmpfs
    (`config::runtime_dir()`, §5) и пересоздаётся при сбое load.
- `src/secret.rs` — единый резолвер:
  - `resolve_all(cfg) -> Result<SecretMap>` — вся карта из бэкенда (TPM: unseal
    DEK + decrypt `map.age`; escrow: decrypt мастер-паролем). Кэш по пути файла
    (`MAP_CACHE`), чтобы разные бэкенды/тесты не сталкивались.
  - `resolve_secret(kind, id) -> Result<Zeroizing<Vec<u8>>>` = `resolve_all` +
    выбор записи `format!("{kind}:{id}")`.
  - `backend_missing(cfg) -> bool` — бэкенд ещё не заенроллен (окно миграции).
  - `SecretMap = BTreeMap<String, Zeroizing<Vec<u8>>>`.
- `src/install.rs` — описанный в §7.1 поток.
- `src/recovery.rs` — §7.2.
- `cli.rs` — `Install { names }`, `Recovery { filter }`.
- `config.rs` — поля `secret_backend` (обязателен), `gpg_preset`, `tpm_ssh`
  (future), `escrow_file`, `master_passphrase_file`, `tpm_pcr`; убраны `keyfile`,
  `gpg_passphrase_file`.
- `gpg.rs` — удалить `extract_secret` и логику `.common-seed`; `preset` через
  `secret::resolve_secret` при `gpg_preset`.
- `mount.rs` — gocryptfs-ключ через `secret::resolve_secret`.
- `check.rs` — §7.3.

## 9. Свойства безопасности

- На диске — только ciphertext (TPM-блобы + escrow под мастер-паролем).
  Plaintext-keyfile из конфиг-дира удалён (реальное улучшение).
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

1. **G = gocryptfs-пароль из промпта `install`** (или env `CRYPT_PASS`), подаётся
   gocryptfs как passphrase через временный passfile (adopt, тома НЕ
   ре-инициализируются). Если нужна генерация свежего ключа + re-init — отдельная
   future-опция.
2. **Escrow plaintext = TOML** (а не bincode) ради читаемости.
3. **TPM: первичный ключ воссоздаётся каждый раз** (без NV-persistence).
4. **config-driven install энроллит ВСЕ ключи** home'а с `gpg_preset` (пустой
   ввод passphrase пропускает конкретный ключ).
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
- **Интерактивный выбор ключей — ОТКЛОНЁН/УДАЛЁН (v0.9.0).** Изначально
  планировался кастомный номерной пикер (`1,3-5`) под `--interactive`, но флаг
  так и остался no-op и удалён. `install` энроллит все primary-ключи home'а;
  ненужный ключ пропускается пустым вводом passphrase.
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

### 11.3. Принято (v0.8.5): DEK-модель вместо per-key TPM-блобов

**Проблема:** TPM запечатывает не более ≈128 байт (проверено: 128 OK, 256 FAIL),
а полная карта секретов больше. Исходный план «по TPM-блобу на запись» вдобавок
светил имена/fingerprint'ы ключей в именах файлов и требовал по
`load`+`unseal` на каждый секрет.

**Решение (стандартная схема, как LUKS+TPM/clevis):**
- `install` генерит случайный 32-байтный **DEK**, запечатывает в TPM **только
  его** (влезает), и шифрует всю карту этим DEK → `map.age`.
- `map.age` — **тот же age-контейнер, что и escrow**; отличается лишь ключ
  обёртки: escrow = мастер-пароль, TPM = DEK. Один сериализованный формат карты,
  две обёртки (требование пользователя: «один формат, по-разному шифруется»).
- Ежедневно: **один** `tpm2_unseal` (DEK) → decrypt всей карты → `Zeroizing`-кэш
  на процесс. Быстрее и без утечки имён на диск.
- `prim.ctx` кэшируется (createprimary ~2 c → один раз; далее mount ~1.1 c).

**Следствия:** `gpg_skip_keys` (имена в конфиге) отклонён в пользу
интерактивного пропуска (пустой Enter). `tpm_gpg` слит с `gpg_preset`. В
`state_dir/tpm/` из TPM-состояния только `dek.priv`, `dek.pub`, `map.age`;
primary-контекст (`prim-<hash>.ctx`) вынесен в per-boot tmpfs (v0.8.6, §5).

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
        `master_passphrase_file`, `tpm_pcr`; per-secret `gpg_preset`. Учтены
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
- [x] **6. `src/install.rs`** + `cli.rs`(`Install{names}`) +
         `main.rs` — единственный writer: `build_map` (G из промпта/`CRYPT_PASS`
         + gpg-пассфразы `gpg_preset`-секретов) → `finalize` (seal TPM + атомарная
         запись escrow). Тесты `finalize_then_recovery_roundtrip_{escrow,tpm}`
         **проходят** (TPM реально). Алиас `inst` (чтобы не конфликтовать с
         `init`=`in`).
- [x] **7. `src/recovery.rs`** + `cli.rs`(`Recovery{filter}`) — `read_map` +
         печать карты (base64). Тесты выше покрывают round-trip.
- [x] **8. `gpg.rs`** — удалены `extract_secret`/`.common-seed`/`gpg_passphrase_file`;
         `preset` через `secret::resolve_secret` при `gpg_preset` (fpr→keygrips
         рантаймом через `keys_with_keygrips`). Без `gpg_preset` → no-op (ручной ввод).
- [x] **9. `mount.rs`** — G через `resolve_secret` (+`passfile::from_bytes`); до
         первого `install` — промпт gocryptfs-пароля (или `CRYPT_PASS`), keyfile
         удалён.
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

## 14. Статус реализации (snapshot: 2026-07-13, v0.8.6)

**Вердикт: реализация завершена + переведена на DEK-модель (§17).** Ежедневный
путь (mount/gpg/check) подключён к бэкенду; изолированные и поведенческие тесты
проходят (39), включая реальный TPM. `cargo clippy --all-targets -D warnings`
чист, без `#![allow(dead_code)]`. v0.8.6: `prim.ctx` перенесён в per-boot tmpfs
(`$XDG_RUNTIME_DIR/sctl/`), см. §5/§17.4.

### Готово и рабочее (проверено)
- Инфраструктура бэкенда: `config`, `escrow` (age scrypt + TOML), `tpm`
  (реальный fTPM 2.0 через `tpm2-tools`), `secret` (`resolve_secret` +
  `OnceLock`-кэш мастер-пароля), `rand` (`random_secret` + тест).
- Команды `install` (alias `inst`) / `recovery` (alias `rc`): единственный
  writer — `build_map` → `finalize` (seal TPM + атомарный escrow). Юнит-тесты
  round-trip зелёные, TPM-тест реально ходит в чип.
- **Шаг 8:** `gpg.rs::preset` через `secret::resolve_secret` при
  `gpg_preset` (fpr→keygrips через `keys_with_keygrips`); `.common-seed`/
  `extract_secret`/`gpg_passphrase_file` удалены.
- **Шаг 9:** `mount.rs` берёт `G` из `resolve_secret` (+`passfile::from_bytes`);
  до первого `install` — промпт gocryptfs-пароля (или `CRYPT_PASS`).
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
- **Финальный дизайн флага gpg:** `tpm_gpg` удалён; `gpg_preset` — единственный
  per-secret флаг «этот gpg-home управляется через бэкенд» (энролл на `install`
  + пресет на `mount`). Механизм (tpm/escrow) выбирается глобально
  `secret_backend`, поэтому `gpg_preset` работает одинаково для обоих бэкендов
  (escrow-энролл/пресет тоже поддержан, не только tpm).
- **Харденинг прав доступа:** `install` пишет эскроу как `0600` независимо от
  umask; TPM-файлы (`dek.priv`/`dek.pub`/`map.age` в `state_dir/tpm/`,
  `prim-*.ctx` в runtime) — `chmod 0600`; `check` предупреждает, если
  `map.age`/эскроу читаемы группой/остальными.
- Фикстуры `tests/common/mod.rs` + `tests/keys_fixture.rs` — проходят.
- **v0.8.5 — DEK-модель (§17):** единый формат карты, escrow=мастер-пароль /
  TPM=sealed-DEK; один unseal на процесс; `prim.ctx`-кэш (mount ~3.8 c → ~1.1 c);
  непрозрачное TPM-состояние (нет fpr в именах файлов); интерактивный пропуск
  ключа (пустой Enter); проверка пароля gpg на месте; `sha2`/per-key блобы
  удалены. Тесты: **39 зелёных**.

### Отложено (документировано, не блокирует)
- **§11.2 Ротация gpg passphrase** — gpg 2.5.20 не меняет passphrase на *другой*
  неинтерактивно; `install` хранит существующий пароль (пресет работает).
- **`tss-esapi`** — выбран fallback `tpm2-tools` (§11.1); своп — опционально.
- **PCR-политика** — `tpm_pcr=true` блокируется явной ошибкой (§5), не реализовано.
- **SSH (`tpm_ssh`)** — future, отдельный opt-in; дизайн и нюансы реализации в §16.

## 15. Первый запуск (`install`) на уже настроенной машине

Случай: конфиг и тома уже есть, gocryptfs-пароль известен. Цель — завести
бэкенд, не сломав существующие тома.

**Главное:** `install` **НЕ регенерирует** ключ томов — он забирает введённый
gocryptfs-пароль как общий `G`. Введи ТОТ ЖЕ пароль, которым уже зашифрованы
тома; регенерация/опечатка сломала бы их (подтверждение пароля в промпте это
страхует).

> Порядок (важно: gpg-хом — это **тоже** зашифрованный том, он должен быть
> примонтирован ДО `install`, иначе enrolment gpg-пароля не найдёт home). Т.к.
> `secret_backend` обязателен, до первого `install` `mount`/`init` спрашивают
> gocryptfs-пароль (или берут `CRYPT_PASS`):

```sh
# 0. примонтируй gpg-том, чтобы ~/.gnupg появился. Бэкенд ещё пуст → sctl
#    спросит gocryptfs-пароль (тот же, которым зашифрованы тома).
sctl mount gpg

# 1. мастер-пароль сессии install — шифрует escrow.
#    Это НОВЫЙ пароль восстановления (не gocryptfs-пароль, не gpg-пароль).
export SCTL_MASTER_PASS='...надёжный пароль восстановления...'

# 2. enrolment: промпт gocryptfs-пароля -> G (seal в TPM); для каждого
#    gpg_preset-ключа — запрос СУЩЕСТВУЮЩЕГО gpg-пароля (сохраняется как есть).
sctl install
#    опц. --names gpg|main|... — заенроллить подмножество секретов.

# 3. проверка (check не блокируется на вводе мастер-пароля).
sctl check
sctl recovery          # base64 gocryptfs:__shared__ — сверь при необходимости

# 4. переключаемся на backend-монтирование (gpg-пароль пресетится из TPM).
sctl umount gpg && sctl mount gpg

# 5. (опц.) харденинг: положи master_passphrase_file (0600) для аварийного
#    восстановления.
```

**Что явно НЕ делается и почему:**
- ключ томов не регенерируется (иначе старые тома не откроются) — `install`
  берёт введённый пароль как `G`.
- gpg-пароль **не ротируется** на случайный (§11.2: gpg 2.5.x не меняет пароль
  неинтерактивно); хранится текущий — пресет работает.
- выбор ключей: `install` проходит по всем primary-ключам gpg-home'а и на каждом
  спрашивает пароль; **пустой Enter пропускает** ключ (v0.8.5, §7.1). Номерной
  пикер (`--interactive`) удалён (v0.9.0, §11.4).
- **SSH**: секрет `ssh` здесь — это gocryptfs-том `~/.ssh`; пароли ssh-ключей
  внутри **не** энроллятся (реализованы только gocryptfs + gpg). SSH-энроллмент —
  future (§16).

**Миграция с ранних сборок (per-key блобы → DEK, v0.8.5):** если TPM-состояние
осталось от версий ≤0.8.2, удали устаревшие per-key файлы перед `install` (новый
формат — `dek.*` + `map.age`):
```sh
rm -f ~/.config/sctl/state/tpm/gpg_gpg_* ~/.config/sctl/state/tpm/gocryptfs___shared__*
rm -f ~/.config/sctl/state/tpm/prim.ctx   # v0.8.6: контекст переехал в $XDG_RUNTIME_DIR/sctl/
# Убери gpg_skip_keys/tpm_gpg из config.toml, если были.
sctl install     # создаст dek.priv/dek.pub/map.age
```

**Gap ре-енролла:** `install` читает `filekey`, а не escrow; если TPM потерян
(смена железа), для повторного `install` нужен `G` из офлайн-бэкапа `filekey`
(или future `install --from-escrow`).

## 16. Идея / отложено: SSH-энроллмент (`tpm_ssh`)

**Цель:** управлять паролями ssh-ключей так же, как gpg-ключами — энроллить в
бэкенд (TPM/escrow) при `install` и пресетить в `ssh-agent` при `mount`, чтобы
не вводить пароль ключа вручную.

**Текущее состояние:** секрет `ssh` в конфиге — это просто gocryptfs-том
`~/.ssh`; пароли ssh-ключей внутри бэкендом **не** трогаются (реализованы
только gocryptfs + gpg). Опция `tpm_ssh` пока не существует.

**Нюансы реализации (когда будем делать):**
- **Обнаружение ключей.** В `~/.ssh` перебрать приватные ключи; для каждого
  определить, защищён ли он паролем — `ssh-keygen -y -P '' -f <key>` падает ⇒
  защищён. Идентификатор аналогичен gpg-fpr: comment ключа либо хэш публичного
  ключа (`ssh-keygen -lf <key>`). Key id в бэкенде: `ssh:<name>:<comment>`.
- **Энроллмент (`install`).** Новый opt-in `tpm_ssh` на секрете (как `gpg_preset`).
  `build_map` для каждого защищённого ключа запрашивает пароль (через тот же
  `GpgPassProvider`/`PromptProvider`) и кладёт `ssh:<name>:<id>` → пароль в
  карту. `composite_key`/`gpg_id_tail` уже параметризованы kind, так что
  добавляется kind `"ssh"`.
- **Пресет при `mount` (главный нюанс).** У gpg есть `gpg-preset-passphrase`
  с чётким API приёма пароля по stdin. У ssh **такого флага нет**: `ssh-add`
  не принимает пароль аргументом/ stdin напрямую — он либо интерактивно
  спрашивает, либо берёт через `SSH_ASKPASS` + `DISPLAY` (или `SSH_ASKPASS_REQUIRE=force`),
  либо через `sshpass -P passphrase ssh-add`. Значит пресет требует либо
  `SSH_ASKPASS`-обёртку, пишущую пароль, либо `sshpass`. Это отдельная
  аккуратная обвязка (аналог `gpg::run_preset`), и она должна учитывать, что
  пароль нельзя оставлять в процессе/логах.
- **Жизненный цикл агента.** `gpg-agent` sctl уже убивает/управляет при
  (пере)монтировании (`gpg_kill`). `ssh-agent` — отдельный;mount не должен его
  убивать (сломает другие сессии), но после mount нужен re-preset (как
  `gpg::preset_all`): пройтись по примонтированным `tpm_ssh`-секретам и
  `ssh-add` их ключи. Убедиться, что `ssh-agent` запущен (завести, если нет).
- **Desync-детектор.** `enrolled_ids` и детектор в `check` должны включать
  `ssh:*` id наравне с `gpg:*`.
- **Ключ без пароля.** Если ключ не защищён паролем — энроллить нечего,
  пресет не нужен; просто пропускать (как gpg пропускает пустые).
- **Безопасность.** Пароль ssh-ключа в памяти — `Zeroizing`; пресет через
  временный `SSH_ASKPASS`-скрипт, удаляемый сразу после `ssh-add`.

## 17. Актуальная архитектура: DEK-модель (v0.8.5, authoritative)

Этот раздел описывает **фактическое** поведение реализации и имеет приоритет над
§3/§5/§7/§8, где ещё упоминаются «per-key TPM-блобы».

### 17.1 Единый формат карты, две обёртки

Один сериализованный `SecretMap` (age-контейнер, plaintext = TOML с base64,
`escrow::seal`/`open`), обёрнутый двумя способами:

| Файл | Обёртка | Назначение |
|------|---------|------------|
| `escrow_file` (`sctl-escrow.age`) | мастер-пароль (age scrypt) | восстановление, переносимо на любую машину |
| `state_dir/tpm/map.age` | **DEK** (age scrypt, «пароль» = base64(DEK)) | ежедневный быстрый путь на этой машине |
| `state_dir/tpm/dek.priv`+`dek.pub` | запечатан в TPM | хранит сам DEK (32 байта) |
| `$XDG_RUNTIME_DIR/sctl/prim-<hash>.ctx` | — (не секрет, per-boot tmpfs) | кэш контекста первичного ключа |

`install` (единственный writer) пишет обе обёртки из одной in-memory карты →
рассинхрон невозможен, если не править файлы руками. Ротация = повторный
`install`.

### 17.2 Почему DEK, а не sealed-карта

TPM запечатывает ≤≈128 байт (проверено: 128 OK / 256 FAIL). Полная карта больше,
поэтому в TPM кладётся только маленький DEK, а карту шифруем этим DEK на диске —
классическая схема (LUKS+TPM, systemd-cryptenroll, clevis).

### 17.3 Поток чтения (mount/gpg)

```
resolve_all(cfg):
  TPM:    DEK = tpm2_unseal(dek.priv,dek.pub via prim.ctx)   # 1 раз на процесс
          map = age_decrypt(map.age, base64(DEK))
  escrow: map = age_decrypt(escrow_file, master)
  → кэш MAP_CACHE[путь] (Zeroizing), далее берём нужные записи
```
Одна TPM-операция отдаёт всю карту; повторные `resolve_secret` бьют в кэш.

### 17.4 Производительность

`tpm2_createprimary` (~1.9 c) выполняется один раз и кэшируется в
`prim-<hash>.ctx` (**runtime-каталог `$XDG_RUNTIME_DIR/sctl/`, tmpfs — не
`state_dir`**, т.к. TPM saved-context живёт лишь до следующего сброса TPM);
далее mount делает только `load`+`unseal`. Замерено: **mount ~3.8 c → ~1.1 c**.
После ребута/`tpm2_clear` контекст устаревает — `load` падает, контекст
пересоздаётся автоматически (первый mount снова ~3.8 c). Хранение в tmpfs точно
совпадает со временем жизни контекста и не мусорит в персистентном state.

### 17.5 Приватность на диске

Никаких fingerprint'ов/имён ключей в файловой системе: только `dek.priv`,
`dek.pub`, `map.age` (в `state_dir/tpm/`) и `prim-<hash>.ctx` (в runtime).
Внутри `map.age` (зашифровано) ключи карты — составные id (`gpg:<name>:<fpr>` и
т.п.), но на диск в открытом виде не попадают.

### 17.6 Пропуск ключа при install

На промпте пароля gpg-ключа **пустой Enter пропускает** ключ (не энроллится).
Пароль проверяется на месте (preset + `--export-secret-keys`; неверный → повтор).
Имена ключей в конфиге не хранятся (`gpg_skip_keys` отклонён). Ctrl+S не
используется (XOFF). Пропущенный ключ просто отсутствует в карте — `check`
не считает это рассинхроном, `mount`/preset его тихо пропускает.

### 17.7 Окно миграции (первый `install`)

Пока бэкенд не заенроллен (`backend_missing`: нет `dek.priv`/`map.age` или
escrow-файла), `mount`/`init` спрашивают gocryptfs-пароль (или берут env
`CRYPT_PASS`) с предупреждением — чтобы можно было примонтировать gpg-том до
первого `install`. На заенролленном бэкенде реальная ошибка unseal
пробрасывается (отката нет).

### 17.8 API (актуальный)

- `tpm.rs`: `seal_dek`, `unseal_dek`, `dek_exists` (+ приватные `ensure_primary`/
  `recreate_primary`, берут `prim-<hash>.ctx` из `config::runtime_dir()`).
- `config.rs`: `runtime_dir()` (`$XDG_RUNTIME_DIR/sctl`, fallback
  `<tmp>/sctl-<uid>`), `primary_ctx_file()` (namespaced по hash(state_dir)).
- `secret.rs`: `resolve_all`, `resolve_secret`, `backend_missing` (кэш `MAP_CACHE`
  по пути файла — изолирует бэкенды и параллельные тесты).
- `install.rs`: `build_map` (G через `GocryptfsKeyProvider`; gpg-skip через
  `Option` от `GpgPassProvider`) → `finalize` (escrow + при TPM: `seal_dek` +
  `map.age`), `write_atomic` (0600).
- `check.rs`: presence (`dek_exists`+`map.age`+права) + desync (сравнение двух
  полных карт).

### 17.9 Что удалено в v0.8.5

- Per-key TPM-блобы (`<id>.priv/.pub`), `tpm::seal/unseal/exists/blob_exists`.
- `gpg_skip_keys` (конфиг), `is_skipped`, `list_primary_keys`, `enrolled_ids`.
- `tpm_gpg` (слит в `gpg_preset`; ещё раньше).
- Зависимость `sha2` (была нужна для непрозрачных per-key имён — больше нет).

### 17.10 Что удалено в v0.9.0

- Plaintext-`keyfile` (поле конфига, env `SCTL_KEYFILE`/`SCTL_KEY`, чтение с
  диска). `G` теперь приходит из промпта `install` (или env `CRYPT_PASS`) и
  живёт только в бэкенде.
- Легаси-режим без `secret_backend`: `secret_backend` стал обязательным
  (`tpm`|`escrow`); `Config.secret_backend` больше не `Option`.
- Флаг `sctl install --interactive` (был no-op) и `InstallOpts.interactive`.
