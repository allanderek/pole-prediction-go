{ pkgs, lib, config, inputs, ... }:
{
  # https://devenv.sh/basics/ to set environment variables is required.

  # https://devenv.sh/packages/
  packages = [
    pkgs.git
    pkgs.entr
    pkgs.fd
    pkgs.sd
    pkgs.sqlite
    pkgs.litecli
    pkgs.vscode-langservers-extracted
  ];

  # See full reference at https://devenv.sh/reference/options/
  languages.go.enable = true;
  languages.elm.enable = true;

  # Add an enterShell script that will run when the environment is entered
  enterShell = ''
    go install github.com/a-h/templ/cmd/templ@latest
    go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
    go install github.com/air-verse/air@latest
    go install github.com/amacneil/dbmate@latest
  '';
}
