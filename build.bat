@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set PATH=%PATH%;%USERPROFILE%\.cargo\bin
cd /d "C:\Users\remic\Documents\Projets Zertree\rust-parser"
cargo build --release
