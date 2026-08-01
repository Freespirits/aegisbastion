@echo off
REM Run golang-migrate inside the compose network against the dev DB.
REM usage: migrate-dev.cmd <command> [args...]   e.g. migrate-dev.cmd down 1
"C:\Program Files\Docker\Docker\resources\bin\docker.exe" run --rm ^
  --network aegisbastion-mvp-a_default ^
  -v E:\aegisbastion\db\migrations:/migrations:ro ^
  migrate/migrate:4 -path=/migrations ^
  -database postgres://aegisbastion:aegisbastion-dev@postgres:5432/aegisbastion?sslmode=disable %*
