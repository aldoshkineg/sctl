# TODO: watch/TPM — диагностика и фикс регрессий переноса runtime-dir

Статус: DONE (исправлено + задеплоено в 0.9.1).

## Важный вывод (проверено strace)
`watch` НЕ делает ни одного `tpm2_*` вызова. Его задача — детект busy + force-
unmount через `fusermount3 -u` (пароль тома для unmount gocryptfs НЕ нужен —
это FUSE, отмонтируется ядром). Второго `tpm2_unseal` в дочернем `watch` НЕТ.
→ Никакого «передавать passfile в watch» делать не надо. Инвариант «watch —
сборщик, не резолвер секретов» УЖЕ соблюдается.

За весь `sctl mount gpg ssh ps` (main + все дочерние watch): ровно **один**
`tpm2_unseal` (в main-процессе). Остальные ~4s — неизбежная стоимость mount:
~2s TPM-unseal DEK (один на процесс) + ~1s gocryptfs_mount + ~1s gpg preset
(4 ключа). Не баг.

## Что РЕАЛЬНО сломалось при переносе эфемерного в /run (исправлено)
Два бага в `move_stray_aside` (src/mount.rs), проявившиеся только когда
`stray_dir` стал `runtime_dir()/stray` (tmpfs, часто на другой ФС, чем
mountpoint):

1. **ENOENT** — `move_stray_aside` делал `create_dir_all(&cfg.runtime_dir())`,
   но не создавал подкаталог `…/stray/` → `rename` падал. Фикс:
   `create_dir_all(cfg.stray_dir())` перед копированием.
2. **EXDEV (Invalid cross-device link)** — `rename(mnt, stray)` между ФС не
   работает (mountpoint на корне, stray в tmpfs `/run`). Фикс: copy+remove
   (`copy_dir` + `remove_dir_all`) вместо `rename`.

## Чек-лист (выполнено)
- [x] `mount gpg` со свежевытертым runtime_dir проходит целиком (вкл. stray-путь).
- [x] stray пишется в `$XDG_RUNTIME_DIR/sctl/stray` (per-boot tmpfs, как и
      задумано).
- [x] strace: ровно 1 `tpm2_unseal` на mount; 0 в `watch`.
- [x] `cargo clippy --all-targets -- -D warnings` + `cargo test` (39 зелёных).
- [x] Бинарь пересобран и задеплоен (`~/.local/bin/sctl` 0.9.1), completions
      обновлены.

## Итог
Плана «убрать TPM из watch» не требуется — watch и так TPM-free. Реальная работа
была в починке двух регрессий переноса runtime-dir в `move_stray_aside`.
Mount одного gpg-секрета ~5.5s (вкл. stray-путь и gpg-preset 4 ключей), трёх
секретов ~4s. Деградация до 10s изначально была от `validate_primary`
(убрано ранее); ENOENT/EXDEV от переноса stray — устранено сейчас.
