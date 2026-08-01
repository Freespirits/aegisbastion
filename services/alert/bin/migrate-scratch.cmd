@echo off
REM Run golang-migrate inside the compose network against a scratch DB.
REM usage: migrate-scratch.cmd <command> [args...]   e.g. migrate-scratch.cmd up
REM Migrations path is resolved relative to this script (repo root = ..\..\..).
setlocal
pushd "%~dp0..\..\.."
set "REPO_ROOT=%CD%"
popd
docker run --rm ^
  --network aegisbastion-mvp-a_default ^
  -v "%REPO_ROOT%\db\migrations":/migrations:ro ^
  migrate/migrate:4 -path=/migrations ^
  -database postgres://aegisbastion:aegisbastion-dev@postgres:5432/aegisbastion_migtest?sslmode=disable %*
endlocal
