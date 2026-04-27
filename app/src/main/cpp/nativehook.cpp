// libdcthook.so — JNI helpers paired with com.dct.hooklogger.NativeHook.
//
// Goals:
//   * Stay tiny and dependency-free (only libc + liblog).
//   * Be safe to call from the bytecode hook path: every method handles I/O failures
//     by returning null/empty/false rather than throwing, so the Kotlin wrapper can
//     fall back to its pure-Kotlin equivalent.

#include <jni.h>
#include <android/log.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <string>
#include <vector>

#define LOG_TAG "DCT-HOOK-NATIVE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace {

constexpr const char* kVersion = "dcthook/1.0";

// Frida-related ports we want stripped from /proc/net/tcp[6] output.
// Hex (uppercase) representations of frida-server's documented defaults: 27042, 27043.
// Speculative entries are intentionally omitted to avoid false positives.
const std::vector<std::string> kFridaPortsHex = {
    "69A2",  // 27042 — frida-server default
    "69A3",  // 27043 — frida-server alt / gadget
};

// ---------- helpers ----------

bool readFile(const char* path, std::string& out) {
    out.clear();
    if (path == nullptr) return false;

    FILE* f = std::fopen(path, "re");
    if (f == nullptr) return false;

    constexpr size_t kChunk = 4096;
    char buf[kChunk];
    while (true) {
        size_t got = std::fread(buf, 1, kChunk, f);
        if (got > 0) out.append(buf, got);
        if (got < kChunk) break;
    }
    std::fclose(f);
    return true;
}

std::string toUpperHex(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    return out;
}

// Returns true when the line's local or remote port column matches one of the
// Frida block-listed ports. The expected format is the standard linux fmt
// "  N: <localAddr>:<localPort> <remoteAddr>:<remotePort> ...".
bool tcpRowIsSuspicious(const std::string& line) {
    // Find the first ':' followed by 4 hex digits then a space — that's the
    // local port column. Then look for the next colon-port pattern.
    size_t pos = 0;
    int colonsSeen = 0;
    while (pos < line.size()) {
        size_t c = line.find(':', pos);
        if (c == std::string::npos) break;
        if (c + 5 > line.size()) break;
        // Check that the 4 chars after ':' are hex.
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            char ch = line[c + 1 + i];
            if (!std::isxdigit(static_cast<unsigned char>(ch))) { ok = false; break; }
        }
        if (ok) {
            std::string port = toUpperHex(line.substr(c + 1, 4));
            for (const auto& bp : kFridaPortsHex) {
                if (port == bp) return true;
            }
            colonsSeen++;
            if (colonsSeen >= 2) break;
        }
        pos = c + 1;
    }
    return false;
}

std::string sanitizeStatusBuffer(const std::string& in) {
    std::string out;
    out.reserve(in.size());

    size_t pos = 0;
    while (pos < in.size()) {
        size_t end = in.find('\n', pos);
        if (end == std::string::npos) end = in.size();
        std::string line = in.substr(pos, end - pos);
        if (line.compare(0, 10, "TracerPid:") == 0) {
            out.append("TracerPid:\t0");
        } else {
            out.append(line);
        }
        if (end < in.size()) out.push_back('\n');
        pos = (end == std::string::npos) ? in.size() : end + 1;
    }
    return out;
}

std::string sanitizeProcNetTcpBuffer(const std::string& in) {
    std::string out;
    out.reserve(in.size());

    size_t pos = 0;
    while (pos < in.size()) {
        size_t end = in.find('\n', pos);
        if (end == std::string::npos) end = in.size();
        std::string line = in.substr(pos, end - pos);
        if (!tcpRowIsSuspicious(line)) {
            out.append(line);
            if (end < in.size()) out.push_back('\n');
        }
        pos = (end == std::string::npos) ? in.size() : end + 1;
    }
    return out;
}

bool mapsContains(const char* path, const std::string& needleLower) {
    FILE* f = std::fopen(path, "re");
    if (f == nullptr) return false;

    char* line = nullptr;
    size_t cap = 0;
    bool found = false;
    while (true) {
        ssize_t n = ::getline(&line, &cap, f);
        if (n <= 0) break;
        // case-insensitive contains
        std::string l(line, static_cast<size_t>(n));
        std::transform(l.begin(), l.end(), l.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (l.find(needleLower) != std::string::npos) {
            found = true;
            break;
        }
    }
    if (line != nullptr) std::free(line);
    std::fclose(f);
    return found;
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_dct_hooklogger_NativeHook_nativeVersionImpl(JNIEnv* env, jclass /*clazz*/) {
    return env->NewStringUTF(kVersion);
}

JNIEXPORT jstring JNICALL
Java_com_dct_hooklogger_NativeHook_nativeSanitizedStatusFile(
        JNIEnv* env, jclass /*clazz*/, jstring jPath) {
    if (jPath == nullptr) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jPath, nullptr);
    std::string buf;
    bool ok = readFile(path, buf);
    env->ReleaseStringUTFChars(jPath, path);
    if (!ok) return env->NewStringUTF("");

    std::string sanitized = sanitizeStatusBuffer(buf);
    return env->NewStringUTF(sanitized.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_dct_hooklogger_NativeHook_nativeSanitizedProcNetTcp(
        JNIEnv* env, jclass /*clazz*/, jstring jPath) {
    if (jPath == nullptr) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jPath, nullptr);
    std::string buf;
    bool ok = readFile(path, buf);
    env->ReleaseStringUTFChars(jPath, path);
    if (!ok) return env->NewStringUTF("");

    std::string sanitized = sanitizeProcNetTcpBuffer(buf);
    return env->NewStringUTF(sanitized.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_dct_hooklogger_NativeHook_nativeIsLibraryMapped(
        JNIEnv* env, jclass /*clazz*/, jstring jNeedle) {
    if (jNeedle == nullptr) return JNI_FALSE;
    const char* raw = env->GetStringUTFChars(jNeedle, nullptr);
    std::string needle(raw);
    env->ReleaseStringUTFChars(jNeedle, raw);
    if (needle.empty()) return JNI_FALSE;

    std::transform(needle.begin(), needle.end(), needle.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return mapsContains("/proc/self/maps", needle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_dct_hooklogger_NativeHook_nativeAppendLogLine(
        JNIEnv* env, jclass /*clazz*/, jstring jPath, jstring jLine) {
    if (jPath == nullptr || jLine == nullptr) return -1;

    const char* path = env->GetStringUTFChars(jPath, nullptr);
    const char* line = env->GetStringUTFChars(jLine, nullptr);
    int written = -1;

    int fd = ::open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd >= 0) {
        size_t lineLen = std::strlen(line);
        ssize_t n = ::write(fd, line, lineLen);
        if (n >= 0 && static_cast<size_t>(n) == lineLen) {
            ssize_t nl = ::write(fd, "\n", 1);
            if (nl == 1) written = static_cast<int>(lineLen + 1);
        }
        ::close(fd);
    } else {
        LOGW("appendLogLine: open(%s) failed", path);
    }

    env->ReleaseStringUTFChars(jPath, path);
    env->ReleaseStringUTFChars(jLine, line);
    return written;
}

}  // extern "C"
