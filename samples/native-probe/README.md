# Native injection probe

This minimal payload verifies the Akane kernel module, ELF loader, bootstrap,
and `.init_array` execution without involving Frida, GumJS, JNI, or ART.

Build it with Android NDK r26:

```sh
cd samples/native-probe
"$ANDROID_NDK_HOME/ndk-build" \
  NDK_PROJECT_PATH="$PWD" \
  APP_BUILD_SCRIPT="$PWD/jni/Android.mk" \
  NDK_APPLICATION_MK="$PWD/jni/Application.mk"
```

Deploy the resulting payload and inject it into a process you are authorized
to test:

```sh
adb push libs/arm64-v8a/libakane-native-probe.so /data/local/tmp/
adb shell su -c \
  '/data/local/tmp/akane-injector -p <pid> -s /data/local/tmp/libakane-native-probe.so -vv'
```

A successful constructor call emits:

```text
I AkaneNativeProbe: constructor reached in pid=<pid>
```

Check it with:

```sh
adb logcat -d -s AkaneNativeProbe:I '*:S'
```
