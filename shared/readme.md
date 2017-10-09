# Build goflyway as a shared library

Thanks to the work done by golang, we can generate static library *.a from go sources, thus, build `dll` or `so`.

Note that `-buildmode=c-archive` on 386 is not supported by Windows, on Linux 64bit, you should `apt-get install g++-multilib` first.