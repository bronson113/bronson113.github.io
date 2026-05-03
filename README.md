# bronson113.github.io

Local development for this site is just a Jekyll server. The repo does not currently include a Decap CMS admin config, so Node.js is not required for normal editing and previewing.

## Prerequisites

- Ruby 3.3.x
- Bundler 4.x

Ruby 4.0 does install the gems in this repo, but the current GitHub Pages/Jekyll stack does not run on Ruby 4.0. During verification it failed inside `liquid 4.0.3` on `String#untaint`, which was removed in Ruby 4.0.

GitHub Pages currently documents Ruby `3.3.4` in its dependency versions page, so Ruby 3.3 is the safest local match.

## First-time setup

If you do not already have Ruby 3.3, install it first. Homebrew currently provides `ruby@3.3`:

```bash
brew install ruby@3.3
```

Then use that Ruby for this repo:

```bash
export PATH="/opt/homebrew/opt/ruby@3.3/bin:$PATH"
ruby -v
```

Install the dependencies:

```bash
bundle config set --local path vendor/bundle
bundle install
```

## Run locally

Start the Jekyll dev server with livereload:

```bash
bundle exec jekyll serve --livereload
```

The site will be available at:

```text
http://127.0.0.1:4000
```

## Quick start

After dependencies are installed, you can also use:

```bash
./webserver_run.sh
```

## Notes

- `package-lock.json` is currently unused for the local site preview flow.
- `vendor/bundle` is used so local gem installs stay inside the repo.
- If you accidentally run under Ruby 4.0, Jekyll currently fails during build because the older GitHub Pages stack still depends on APIs removed in Ruby 4.0.
