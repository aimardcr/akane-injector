#include <android/log.h>
#include <unistd.h>

__attribute__((constructor))
static void akane_native_probe_init(void)
{
	__android_log_print(ANDROID_LOG_INFO,
			    "AkaneNativeProbe",
			    "constructor reached in pid=%d",
			    getpid());
}
