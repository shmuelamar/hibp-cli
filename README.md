# Have I Been Pwned CLI

simple [haveibeenpwned.com](https://haveibeenpwned.com) command line for checking breachse of accounts using HIBP API v2.

Note: all data is fetched from haveibeenpwned.com, I own none of the data and special thanks goes
to @troyhunt for sharing this info freely for safer online world.

please read the [rate limits](https://haveibeenpwned.com/API/v2#RateLimiting) of haveibeenpwned.com and honor them,
use this software on your own risk.

## Download

download for windows linux or osx available at the [releases](https://github.com/shmuelamar/hibp-cli/releases) page

## Usage

command line help:

```bash
Usage:
  hibp-cli [OPTIONS]

Application Options:
  -a, --account=       account to search leaks for
  -f, --filename=      input filename of account to search, one account per line
  -o, --output=        output filename for detailed json-lines response
  -d, --request-delay= request delay between each api call, default 10s

Help Options:
  -h, --help           Show this help message

```


## Create New Release

run:

```bash
make release
```
