#include <jni.h>

#include <SDL3/SDL.h>

#include "platform.hpp"

namespace internet {
namespace platform {

namespace {

class Activity {
public:
    Activity()
        : env_(static_cast<JNIEnv*>(SDL_GetAndroidJNIEnv())), activity_(static_cast<jobject>(SDL_GetAndroidActivity())) {}

    ~Activity() {
        if (env_ && activity_) env_->DeleteLocalRef(activity_);
    }

    Activity(const Activity&) = delete;
    Activity& operator=(const Activity&) = delete;

    bool valid() const { return env_ != nullptr && activity_ != nullptr; }

    jmethodID method(const char* name, const char* signature) {
        jclass type = env_->GetObjectClass(activity_);
        jmethodID id = env_->GetMethodID(type, name, signature);
        env_->DeleteLocalRef(type);
        if (env_->ExceptionCheck()) {
            env_->ExceptionClear();
            return nullptr;
        }
        return id;
    }

    bool finish() {
        if (env_->ExceptionCheck()) {
            env_->ExceptionClear();
            return false;
        }
        return true;
    }

    JNIEnv* env() { return env_; }
    jobject object() { return activity_; }

private:
    JNIEnv* env_;
    jobject activity_;
};

}

bool shareText(const std::string& text) {
    Activity activity;
    if (!activity.valid()) return false;
    jmethodID method = activity.method("shareText", "(Ljava/lang/String;)V");
    if (!method) return false;
    jstring value = activity.env()->NewStringUTF(text.c_str());
    activity.env()->CallVoidMethod(activity.object(), method, value);
    activity.env()->DeleteLocalRef(value);
    return activity.finish();
}

void haptic(int milliseconds) {
    Activity activity;
    if (!activity.valid()) return;
    jmethodID method = activity.method("vibrate", "(I)V");
    if (!method) return;
    activity.env()->CallVoidMethod(activity.object(), method, static_cast<jint>(milliseconds));
    activity.finish();
}

std::string takeLaunchLink() {
    Activity activity;
    if (!activity.valid()) return std::string();
    jmethodID method = activity.method("takeLaunchLink", "()Ljava/lang/String;");
    if (!method) return std::string();
    jstring value = static_cast<jstring>(activity.env()->CallObjectMethod(activity.object(), method));
    if (!activity.finish() || value == nullptr) return std::string();
    const char* chars = activity.env()->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars) activity.env()->ReleaseStringUTFChars(value, chars);
    activity.env()->DeleteLocalRef(value);
    return result;
}

void setHosting(bool active, const std::string& name) {
    Activity activity;
    if (!activity.valid()) return;
    jmethodID method = activity.method("setHosting", "(ZLjava/lang/String;)V");
    if (!method) return;
    jstring value = activity.env()->NewStringUTF(name.c_str());
    activity.env()->CallVoidMethod(activity.object(), method, static_cast<jboolean>(active ? JNI_TRUE : JNI_FALSE), value);
    activity.env()->DeleteLocalRef(value);
    activity.finish();
}

}
}
