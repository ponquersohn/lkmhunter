
if [ -z $1]
then
    KERNEL_VERSION=$(uname -r)
else
    KERNEL_VERSION=$1
fi

while read line; do echo $line  ; done << EOF > .vscode/c_cpp_properties.json
{
    "configurations": [
        {
            "name": "driver",
            "defines": [
                "__KERNEL__",
                "MODULE"
            ],
            "compilerPath": "/usr/bin/gcc",
            "cStandard": "c11",
            "cppStandard": "c++14",
            "intelliSenseMode": "gcc-x64",
            "includePath": [
                "/usr/src/linux-headers-$KERNEL_VERSION/arch/x86/include",
                "/usr/src/linux-headers-$KERNEL_VERSION/arch/x86/include/generated",
                "/usr/src/linux-headers-$KERNEL_VERSION/include",
                "/usr/src/linux-headers-$KERNEL_VERSION/arch/x86/include/uapi",
                "/usr/src/linux-headers-$KERNEL_VERSION/arch/x86/include/generated/uapi",
                "/usr/src/linux-headers-$KERNEL_VERSION/include/uapi",
                "/usr/src/linux-headers-$KERNEL_VERSION/include/generated/uapi",
                "/usr/src/linux-headers-$KERNEL_VERSION/ubuntu/include",
                "/usr/lib/gcc/x86_64-linux-gnu/11/include"
            ],
            "compilerArgs": [
                "-nostdinc",
                "-include",
                "/usr/src/linux-headers-5.4.0-39-generic/include/linux/kconfig.h",
                "-include",
                "/usr/src/linux-headers-5.4.0-39-generic/include/linux/compiler_types.h"
            ]
        }
    ],
    "version": 4
}
EOF