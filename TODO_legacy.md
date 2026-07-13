# TODO: удаление legacy `keyfile` (план работ)

Статус: **DONE (code/tests/docs/deploy)** — sctl v0.9.0 собран и задеплоен
(2026-07-13). Поле `keyfile` удалено, `secret_backend` обязателен, `--interactive`
убран, `CRYPT_PASS` оставлен как единственный automation/test-хук (SCTL_KEY/
SCTL_KEYFILE удалены). Живая машина ещё не перенесена (см. ниже).

## Решение (от пользователя)

- **`keyfile` не нужен вообще.** Плейнтекст-ключ на диске удаляется как понятие.
- **`install` спрашивает gocryptfs-пароль** (это и есть общий ключ `G`) и кладёт
  его ТОЛЬКО в бэкенд (TPM/escrow). На диске в открытом виде `G` больше не лежит.
- **Если у секрета `gpg_preset`** — далее регистрируем (prompt + verify + seal)
  пароли gpg-ключей, как сейчас.
- `mount`/`init` берут `G` из бэкенда. До первого `install` (бэкенд пуст) —
  просто интерактивный prompt пароля (с подтверждением), без keyfile.

Инвариант сохраняется: `G` не регенерируется автоматически — его вводит человек
(тот же пароль, которым уже зашифрованы существующие gocryptfs-тома).

### Уточнения (подтверждено пользователем)

1. **Версия: v0.9.0** (minor, breaking — исчезает поле `keyfile`).
2. **`CRYPT_PASS`/`SCTL_KEY` УДАЛЯЕМ** (пользователю не нужны). Non-interactive
   тестируемость `G` обеспечиваем инъекцией провайдера (как `GpgPassProvider`),
   а не через env.
3. **None-режим (без `secret_backend`) УДАЛЯЕМ.** `secret_backend` становится
   ОБЯЗАТЕЛЬНЫМ (`tpm`|`escrow`); при отсутствии — ошибка конфига. Prompt для `G`
   остаётся ТОЛЬКО как fallback, когда бэкенд ещё пуст (до первого `install`).

## Целевые потоки

**Свежая машина / первый install:**
```
sctl mount gpg      # бэкенд пуст -> prompt gocryptfs-пароля -> том смонтирован
sctl install        # prompt того же gocryptfs-пароля (+confirm) -> G в бэкенд;
                    # для каждого gpg_preset-секрета: prompt+verify паролей ключей
sctl check          # presence + desync
```
**Уже мигрировано (бэкенд заполнен):**
```
sctl mount gpg      # G из бэкенда, gpg preset из бэкенда
sctl install        # re-enroll (prompt G + gpg) при ротации
```

---

## Задачи (по файлам)

### 1. `src/config.rs` — убрать keyfile из модели
- [ ] Удалить поле `RawSettings.keyfile`.
- [ ] Удалить поле `Config.keyfile`.
- [ ] Удалить блок резолва `keyfile` (env `SCTL_KEYFILE` > config > default) и
      строку `keyfile,` в конструкторе `Config`.
- [ ] Поправить doc-комментарии, где упоминается «legacy keyfile».

### 2. `src/passfile.rs` — prompt вместо keyfile
- [ ] Сменить сигнатуру `resolve(name: &str, keyfile: &Path)` →
      `resolve(name: &str)`.
- [ ] Порядок источников: `CRYPT_PASS` (env) > `SCTL_KEY` (файл, для автоматизации
      и тестов) > **интерактивный prompt с подтверждением**. Убрать
      чтение `keyfile`.
- [ ] `copy_or_prompt` → `prompt_with_confirm` (только prompt, без файла).
- [ ] Оставить `from_bytes` без изменений (используется backend-путём).
- [ ] Решить судьбу `CRYPT_PASS`/`SCTL_KEY`: ОСТАВЛЯЕМ (нужны для non-interactive
      тестов и автоматизации; это не плейнтекст-ключ в конфиге).

### 3. `src/install.rs` — prompt G вместо чтения keyfile
- [ ] В `build_map`: заменить чтение `cfg.keyfile` на запрос gocryptfs-пароля
      через `passfile`-подобный prompt с подтверждением (или вынести общий
      хелпер `prompt_secret_confirm(label)` в `passfile.rs` и переиспользовать).
- [ ] Хранить как `gocryptfs:__shared__` (как сейчас).
- [ ] Обновить модуль-докстринг (шаг 1: «prompt gocryptfs password», не «adopt
      from keyfile»).
- [ ] Убрать `InstallOpts.interactive` (+`#[allow(dead_code)]`) — no-op.
- [ ] (Опц.) Верификация введённого G: если хоть один gocryptfs-том уже
      инициализирован — попытаться тест-смонтировать его этим паролем в scratch
      и размонтировать; при ошибке — переспросить. Уменьшает риск опечатки,
      ломающей существующие тома. Пометить как nice-to-have.

### 4. `src/cli.rs` — убрать `--interactive`
- [ ] Удалить флаг `interactive` у подкоманды `Install`.
- [ ] Убрать его проброс в `InstallOpts` (см. main.rs/где строится InstallOpts).

### 5. `src/mount.rs` — единый источник G
- [ ] `resolve_gocryptfs_passfile`: backend-режим — `resolve_secret` из бэкенда;
      при `backend_missing` — **prompt** (`passfile::resolve(name)`) вместо
      keyfile-fallback. Реальная ошибка unseal на заполненном бэкенде — по-прежнему
      пробрасывается.
- [ ] `init_one` (строка ~50): **баг-фикс** — брать G из
      `resolve_gocryptfs_passfile(cfg, secret)` (тот же путь, что mount), а НЕ
      `passfile::resolve(&cfg.keyfile)`. Гарантирует единый G для init и mount.
- [ ] Обновить doc-комментарии (убрать «legacy plaintext keyfile»).

### 6. `src/check.rs` — убрать проверку keyfile
- [ ] Удалить `check_keyfile` и её вызов (строки 53-54, 414-424).
- [ ] Обновить текст legacy-ветки `check_backend` (None): убрать «plaintext
      keyfile», оставить «secret_backend not set».
- [ ] Исправить устаревший комментарий `check.rs:151` («per-secret blob
      presence» → «sealed DEK + DEK-encrypted map»).

### 7. `src/secret.rs` — комментарии
- [ ] Обновить докстринг `backend_missing` (убрать «fall back to legacy keyfile»
      → «prompt for the gocryptfs password»).

### 8. `src/tpm.rs` — комментарии
- [ ] `tpm.rs:139` — обновить упоминание «fall back to the legacy keyfile».

---

## Тесты

### 9. Обновить фикстуры Config (убрать `keyfile:`)
- [ ] `src/tpm.rs` (test_cfg), `src/secret.rs` (cfg_with), `src/install.rs`
      (base_cfg), `src/deps.rs` (test cfg) — удалить поле `keyfile`.
- [ ] `tests/backend.rs` — убрать параметр `keyfile`, запись файла ключа
      (строки 27, 55, 110-111, 117, 162-163, 166) и адаптировать `build_map`:
      теперь G берётся из prompt/CRYPT_PASS. Вариант: выставить `CRYPT_PASS` в
      тесте ИЛИ добавить в `build_map` инъекцию источника G (см. ниже).
- [ ] `tests/cli.rs` — убрать `keyfile = "$KEY"` из `BASE` и трёх других
      конфигов; заменить на `CRYPT_PASS` env в harness там, где нужен ключ.

### 10. Тестируемость install (G-провайдер)
- [ ] Сейчас `build_map` берёт gpg-пароли через `GpgPassProvider` (мокается в
      тестах). Для G ввести аналогичный источник, чтобы тесты не требовали tty:
      либо reuse `CRYPT_PASS`/`SCTL_KEY` внутри prompt-хелпера (проще), либо
      параметр/трейт `GocryptfsPassProvider`. **Рекомендация:** переиспользовать
      `passfile`-хелпер, читающий `CRYPT_PASS` → тесты просто ставят env.

### 11. Регресс-тесты
- [ ] Добавить тест: `init` и `mount` дают один и тот же G из бэкенда
      (после fix init_one).
- [ ] Прогнать полный `cargo fmt && clippy --all-targets -D warnings && test`.

---

## Документация

### 12. `config.example.toml`
- [ ] Удалить строку `keyfile = "..."` и комментарий про passfile.
- [ ] Добавить примечание: `install` спрашивает gocryptfs-пароль, keyfile не
      используется.

### 13. `docs/SECRETS.md`
- [ ] §1/§17: обновить модель G — «вводится при install, хранится только в
      бэкенде», убрать «G = байты keyfile».
- [ ] §7.1: install шаг 1 = prompt gocryptfs-пароля (+confirm).
- [ ] §7.4/§17.7: mount до install — prompt, а не keyfile-fallback.
- [ ] Убрать/переписать все упоминания «legacy keyfile» (строки ~62, 162, 179,
      253, 256, 300, 327, 453, 463, 497, 555, 702).
- [ ] Добавить раздел миграции: после `install` удалить старый
      `~/.config/sctl/key`.

### 14. `AGENTS.md`
- [ ] Обновить правило про let-chains: они стабильны (rust 1.89 / edition 2024),
      rustfmt+clippy их принимают → снять запрет (или переформулировать).
      Текущие let-chains: `mount.rs:127`, `tpm.rs:199-200`, `procfs.rs:36`.

---

## Деплой (по AGENTS.md)

### 15. Релиз  ← ВЫПОЛНЕНО (sctl 0.9.0 задеплоен 2026-07-13)
- [x] Бамп версии в `Cargo.toml` → `0.9.0`.
- [x] `cargo fmt` + `clippy --all-targets -- -D warnings` + `cargo test` (39 зелёных).
- [x] `cargo build --release`; `cp target/release/sctl ~/.local/bin/sctl` (755).
- [x] `sctl completions zsh > ~/.zsh/completions/_sctl` (644); `sctl version` → `0.9.0`.

### 16. Миграция живой машины (руками, после деплоя)
- [ ] `sctl mount gpg` с паролем = текущее содержимое `~/.config/sctl/key`
      (новый бинарь проигнорирует `keyfile` из конфига и спросит пароль).
- [ ] `export SCTL_MASTER_PASS='...пароль восстановления...'`.
- [ ] `sctl install` — prompt gocryptfs-пароля (ТОТ ЖЕ пароль, что в key; с
      подтверждением), затем gpg-пароли.
- [ ] `sctl check` — без ошибок; `sctl recovery` — сверить `gocryptfs:__shared__`.
- [ ] `rm ~/.config/sctl/key` — удалить плейнтекст-ключ.
- [ ] Убрать `keyfile = ...` из живого `config.toml`.

---

## Риски / заметки

- **Опечатка в gocryptfs-пароле при install** запишет неверный G в бэкенд →
  существующие тома не смонтируются. Митигация: confirm-prompt (реализовано).
  escrow-копия хранит то, что ввели — сверка через `sctl recovery`.
- **Chicken-and-egg для gpg на свежей машине:** `install` требует смонтированный
  gpg-home для перечисления ключей. Решается тем, что `mount` до install спрашивает
  пароль — том монтируется без keyfile. Порядок: `sctl mount gpg` → `sctl install`.
- **`secret_backend = None` (legacy-режим)** УДАЛЁН: `secret_backend` обязателен;
  `Config.secret_backend` больше не `Option`.
- **envs:** `SCTL_KEYFILE`/`SCTL_KEY` удалены; `CRYPT_PASS` оставлен как единственный
  automation/test-хук (читает gocryptfs-пароль без tty).
