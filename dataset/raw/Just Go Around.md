# Just Go Around

Square 2023 Web CTF challenge

## Description

This website is a forum where people can make posts, though it's so broken
right now that you can probably only search them. It turns out that someone
posted something top secret and later deleted it, but was it truly deleted?

## Hints

1. Have you heard of "soft deletes"?

## Notes

This challenge runs in two containers: An app container and a db container.
The flag starts in a text file in the app container, but the app reads the
file, writes the contents to the db, then deletes the file. That way,
participants can't just use LFI to read the flag from files/source/env/etc.

## Solution

The index page of the website provides a search feature that performs fuzzy
text search, which should indicate that it uses a modern NoSQL DB. There's
also a commented out link to the post page where you can attempt to create a
new post, but when you submit the post, you are redirected to another page
that says this feature no longer works. However, you can look at the HTTP
requests used in that workflow and see that the post is serialized into XML
before submitting, which should prompt you to try an XXE attack. Once you get
that working, your goal is to use the XXE as an SSRF to query the backend
elasticsearch db and get the "deleted" post. You can get the DB host name "db"
by guessing/brute forcing or using the XXE for LFI and reading source/config
files (or the env file)