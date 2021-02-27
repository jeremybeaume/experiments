# A binary with no imports

This experiment is a binary with complexe functionaly, but no import table.

It uses the PEB to find `kernel32.dll`, then gets to `LoadLibrary` and `GetProcAddress`.

More details on the corresponding blog post here : [https://bidouillesecurity.com/windows-peb-parsing-a-binary-with-no-imports](https://bidouillesecurity.com/windows-peb-parsing-a-binary-with-no-imports)
