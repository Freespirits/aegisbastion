@echo off
REM Run golang-migrate inside the compose network against a scratch DB.
REM usage: migrate-scratch.cmd <command> [args...]   e.g. migrate-scratch.cmd up
"C:\Program Files\Docker\Docker\resources\bin\docker.exe" run --rm ^
  --network aegisbastion-mvp-a_default ^
  -v E:\aegisbastion\db\migrations:/migrations:ro ^
  migrate/migrate:4 -path=/migrations ^
  -database postgres://aegisbastion:aegisbastion-dev@postgres:5432/aegisbastion_migtest?sslmode=disable %*
