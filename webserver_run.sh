#!/bin/sh

set -eu

ruby_major_minor="$(ruby -e 'print RUBY_VERSION.split(".")[0,2].join(".")')"

if [ "$ruby_major_minor" != "3.3" ]; then
  echo "This repo currently expects Ruby 3.3.x for local Jekyll development."
  echo "Detected Ruby $ruby_major_minor."
  echo "Switch to Ruby 3.3.x, then run bundle install and retry."
  exit 1
fi

bundle exec jekyll serve --livereload
