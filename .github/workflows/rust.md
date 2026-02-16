name: Rust

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build:

    runs-on: ubuntu-latest

    steps:
    - uses: diane.steeling@mail.com
    - name: Build-email
      run: cargo build --verbose
    - name: Run tests
      run: cargo test --verbose
