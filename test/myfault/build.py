import os
import subprocess


def check_edk2build_image(img_name):
    process = subprocess.Popen(
        ["docker", "images", f"{img_name}"], stdout=subprocess.PIPE
    )
    output, _ = process.communicate()
    output = output.decode()
    print(output)
    return False if output.find(f"{img_name}") == -1 else True


def check_build_container(cname):
    process = subprocess.Popen(["docker", "ps", "-a"], stdout=subprocess.PIPE)
    output, _ = process.communicate()
    output = output.decode()
    print(output)
    return False if output.find(cname) == -1 else True


def build():
    container_name = "buildmyfault"
    image_name = "edk2build"
    if check_edk2build_image(image_name) == False:
        print(f"[*]Building {image_name} images!")
        os.system(f"docker buildx build --platform=linux/amd64 . -t {image_name}")
    else:
        print(f"[*]Found {image_name} images!")

    if check_build_container(container_name) == False:
        print(f"[*]Creating new container name is {container_name}!")
        buildcmd = f"docker run \
    -v$(pwd):/tiano/edk2/myfault \
    -v$(pwd)/compile.sh:/tiano/compile.sh \
    -v$(pwd)/target.txt:/tiano/edk2/Conf/target.txt \
    -v$(pwd)/MdeModulePkg.dsc:/tiano/edk2/MdeModulePkg/MdeModulePkg.dsc  \
    --name {container_name} {image_name} /tiano/compile.sh"
    else:
        print(f"[*]Using exist container {container_name}!")
        buildcmd = f"docker start {container_name} && docker exec {container_name}  /tiano/compile.sh"
    os.system(buildcmd)


build()
