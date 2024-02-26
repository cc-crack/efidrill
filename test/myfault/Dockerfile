FROM --platform=linux/amd64 ubuntu:18.04


WORKDIR /tiano

RUN apt update && apt install -y \
        bc \
        bison \
        build-essential \
        cpio \
        flex \
        libelf-dev \
        libncurses-dev \
        libssl-dev \
        vim-tiny \
        zsh\
        wget\
        nasm iasl uuid-dev\
        python
RUN useradd -u 1001 -m dev && chown dev:dev /tiano
USER dev


RUN mkdir edk2 && \
    wget https://github.com/tianocore/edk2/releases/download/vUDK2017/edk2-vUDK2017.tar.gz&& \
    tar xvf edk2-vUDK2017.tar.gz --strip-components=1 -C ./edk2 &&\
    make -C edk2/BaseTools \