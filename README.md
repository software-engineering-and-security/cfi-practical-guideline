# SoK: Preventing Real-World Exploits: A Practical Guideline and Taxonomy to LLVM's Control Flow Integrity
Access artifacts via the following [OSF link](https://osf.io/xt3w2/?view_only=fb28e23824bc470eb80970bcfbc6dcb4).

## General
All containers are created using podman, however, it is also possible to use them with Docker.  
The installation instructions for podman can be found [here](https://podman.io/docs/installation) and for Docker [here](https://docs.docker.com/engine/install/) or [here](https://www.docker.com/get-started/).  

----------

For each CVE we have a separate container which was exported into a `.tar` file and can be found in the different folders respectively.  
They can be __imported__ and __used__ by:  
```
# Restore container as a new image
podman import <container>.tar <your_image>

# Run and enter the container
podman run -it --name <your_container_name> --user exploit <your_image>

# Start and enter the container if it is already created
podman start <your_container_name>
podman exec -it --user exploit <your_container_name> /bin/bash
```

For __Docker__ the commands are the same just `podman` needs to be replaced with `docker`.  

How to trigger the PoCs/expoits with and without CFI is described within the directory of the CVEs.


## Using the different CVEs
###  Heap-based Buffer Overflow - CVE-2021-3156
Sudo before 1.9.5p2 contains an off-by-one error that can result in a **heap-based buffer overflow**, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character [[NVD](https://nvd.nist.gov/vuln/detail/cve-2021-3156)].  
`sudo apt-get install clang lld make`  
#### __Reproduction steps:__
#### 1. Getting sudo
##### i. Download the source code
`git clone https://github.com/sudo-project/sudo.git`  
`cd sudo`  
`git checkout tags/SUDO_1_8_21p2`

##### ii. Building sudo
`./configure CC=clang`  
`make`
##### iii. Configuring sudo for execution
`./conf_sudo <absolut/path/to/sudo/directory>`

#### 2. The exploit
##### Getting the exploit
`git clone https://github.com/CptGibbon/CVE-2021-3156`  
`cd CVE-2021-3156`  
##### Adjusting exploit to run local --and not system-- sudo
`sed -i 's#/usr/bin/sudoedit#/home/exploit/sudo/src/.libs/sudoedit#g' exploit.c `  
`make`
##### Executing the exploit
`./exploit`  
Expected output (root shell): `# `

#### 3. The exploit with CFI
##### i. Building with CFI (__cfi-icall__ replace with other CFI variant) 
```text
./configure CC=clang CXX=clang++ \ 
	CFLAGS='-flto -fvisibility=hidden -fsanitize=cfi-icall -fno-sanitize-trap=cfi-icall' \ 
	CXXFLAGS='-flto -fvisibility=hidden -fsanitize=cfi-icall -fno-sanitize-trap=cfi-icall' \ 
	LDFLAGS='-flto -fvisibility=hidden -fsanitize=cfi-icall -fuse-ld=lld -fno-sanitize-trap=cfi-icall'
```
`make`  
Configure the new sudo to make it executable
`../conf_sudo /home/exploit/cfi_icall/`  
##### ii. Preparing the exploit
`make <cfi-variant>`
##### iii. Running the exploit for a specific CFI variant
`./<cfi-variant>_exploit`


----------

### Stack-based Buffer Overflow - CVE-2023-49992 
Espeak-ng 1.52-dev was discovered to contain a **Stack Buffer Overflow** via the function RemoveEnding at `dictionary.c` [[NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-49992), [Offical issue](https://github.com/espeak-ng/espeak-ng/issues/1827)].

#### __Reproduction steps:__
#### 1. Get source code and build ([*Official build instructions*](https://github.com/espeak-ng/espeak-ng/blob/master/docs/building.md#building-1))
##### i. Download source code
`git clone https://github.com/espeak-ng/espeak-ng.git`  
##### ii. Install dependencies
```text
sudo apt-get install \ 
	make autoconf automake libtool pkg-config \ 
	gcc g++ clang \ 
	libsonic-dev ronn kramdown \   
	libpcaudio-dev
```
##### iii. Modify source code
In **./src/libespeak-ng/wavegen.c** change `int samplerate = 0;` to `extern int samplerate;`  
##### iv. Build
`./autogen.sh`  
`CC=clang CFLAGS=-Wextra ./configure --prefix=/usr`  
`make`
 
#### 2. The PoC
##### i. Download the PoC
`git clone https://github.com/SEU-SSL/Poc.git`
##### ii. Running the PoC
`export ESPEAK_DATA_PATH=/home/exploit/espeak-ng/espeak-ng-data`

```text
/home/exploit/check_espeak-ng/src/espeak-ng \ 
	-f /home/exploit/Poc/espeak-ng/id_000000,sig_08,src_003156+002428,op_splice,rep_32 \ 
	-w /dev/null
```  

The expected output without protection is: `Floating point exception (core dumped)`[[source](https://www.clouddefense.ai/cve/2023/CVE-2023-49994)]

#### 3. With CFI protection
Replace `cfi-unrelated-cast` with the CFI variant to test.  

```text
CC=clang CXX=clang++ \ 
CFLAGS="-Wextra -fsanitize=cfi-icall -fvisibility=hidden -flto=thin -fno-sanitize-trap=cfi-icall" \ 
CXXFLAGS="-fsanitize=cfi-icall -fvisibility=hidden -flto=thin -fno-sanitize-trap=cfi-icall" \  
LDFLAGS="-flto -fvisibility=hidden -fsanitize=cfi-icall -fuse-ld=lld -Wl,--allow-multiple-definition -fno-sanitize-trap=cfi-icall" \ 
./configure --prefix=/usr
```

```text
ESPEAK_DATA_PATH=/home/exploit/cfi_icall/espeak-ng-data \ 
/home/exploit/cfi_icall/src/espeak-ng \ 
-f /home/exploit/Poc/espeak-ng/id_000000,sig_08,src_003156+002428,op_splice,rep_32 \ 
-w /dev/null
```

----------

### Type Confusion - CVE-2024-34391
libxmljs is vulnerable to a __type confusion__ vulnerability when parsing a specially crafted XML while invoking a function on the result of `attrs()` that was called on a parsed node. This vulnerability might lead to denial of service (on both 32-bit systems and 64-bit systems), data leak, infinite loop and remote code execution (on 32-bit systems with the `XML_PARSE_HUGE` flag enabled) [[NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-34391)].  

#### 1. Building the source
```
npm run build  
"configure": "cd vendor/libxml2.config && cmake configure ../libxml2 && cd ../.."
```

```
cd vendor/libxml2.config
add #define LIBXML_EXPR_ENABLED 1 to config.h
```
```
change "build": "node-gyp rebuild -j max"
to "build": "node-gyp rebuild -j max && npm run tsc" 
```
#### 2. Comiling with CFI
```
CC=clang CXX=clang++ CFLAGS="-flto -fvisibility=hidden -fsanitize=cfi-nvcall -fno-sanitize-trap=cfi-nvcall" CXXFLAGS="-flto -fvisibility=hidden -fsanitize=cfi-nvcall -fno-sanitize-trap=cfi-nvcall" LDFLAGS="-flto -fvisibility=hidden -fsanitize=cfi-nvcall -fuse-ld=lld -fno-sanitize-trap=cfi-nvcall" npm run build
```

`mv build/Release/obj.target/xmljs.node build/Release/`  

#### 3. Executing the PoC   
`./node/out/Release/node exploit.js`  
Expected output: `Segmentation fault (core dumped)`

----------

### Use-After-Free - CVE-2022-3666
A vulnerability, which was classified as critical, has been found in **Axiomatic Bento4**. Affected by this issue is the function `AP4_LinearReader::Advance` of the file `Ap4LinearReader.cpp` of the component `mp42ts`. The manipulation leads to **use after free**. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-212006 is the identifier assigned to this vulnerability[[NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-3666)].  

#### 1. Getting the source code and building Bento4
```
git clone https://github.com/axiomatic-systems/Bento4
cd Bento4
mkdir check_build && cd check_build
cmake ../ -DCMAKE_C_COMPILER=clang DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release`*  
make -j
```
#### 2. Getting the PoC
`wget https://github.com/axiomatic-systems/Bento4/files/9744391/mp42ts_poc.zip`  
`unzip mp42ts_poc.zip`
##### i. Running the PoC
`/home/exploit/Bento4/check_build/mp42ts /home/exploit/mp42ts_poc /dev/null`  
Expected output:   
```
free(): double free detected in tcache 2
Aborted (core dumped)
```

###### ii. Compiling the code with CFI
`sudo apt-get install llvm-10-tools`
```
cmake ../ \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=cfi-icall -fvisibility=hidden -flto=thin" \
  -DCMAKE_CXX_FLAGS="-fsanitize=cfi-icall -fvisibility=hidden -flto=thin" \
  -DCMAKE_EXE_LINKER_FLAGS="-flto -fvisibility=hidden -fsanitize=cfi-icall -fuse-ld=lld" \
  -DCMAKE_BUILD_TYPE=Release
```

