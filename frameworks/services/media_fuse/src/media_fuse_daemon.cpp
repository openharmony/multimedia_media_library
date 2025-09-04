/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaFuseDaemon"
#include "media_fuse_daemon.h"

#include <fcntl.h>
#define FUSE_USE_VERSION 34
#include <fuse.h>
#include <thread>
#include <unistd.h>

#include "dfx_const.h"
#include "dfx_timer.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "media_fuse_manager.h"

namespace OHOS {
namespace Media {
using namespace std;

static constexpr int32_t FUSE_CFG_MAX_THREADS = 5;
static constexpr int32_t USER_AND_GROUP_ID = 2000;
// LCOV_EXCL_START
static int GetAttr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        return MediaFuseManager::GetInstance().DoHdcGetAttr(path, stbuf, fi);
    }
    return MediaFuseManager::GetInstance().DoGetAttr(path, stbuf);
}

static int Open(const char *path, struct fuse_file_info *fi)
{
    int fd = -1;
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_OPEN, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), OPEN_FILE_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    int32_t err = -1;
    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        err = MediaFuseManager::GetInstance().DoHdcOpen(path, fi->flags, fd);
    } else {
        err = MediaFuseManager::GetInstance().DoOpen(path, fi->flags, fd);
    }

    CHECK_AND_RETURN_RET_LOG(err == 0, -ENOENT, "Release: DoOpen failed, path = %{public}s", path);
    fi->fh = static_cast<uint64_t>(fd);
    return E_OK;
}

static int Read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_READ, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    int res = pread(fi->fh, buf, size, offset);
    CHECK_AND_RETURN_RET_LOG(res != -1, -errno, "Read file failed, errno = %{public}d", errno);

    return res;
}

static int Write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_WRITE, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    int res = pwrite(fi->fh, buf, size, offset);
    CHECK_AND_RETURN_RET_LOG(res != -1, -errno, "Read file failed, errno = %{public}d", errno);

    return res;
}

static int Release(const char *path, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_RELEASE, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    int32_t err = -1;
    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        err = MediaFuseManager::GetInstance().DoHdcRelease(path, fi->fh);
    } else {
        err = MediaFuseManager::GetInstance().DoRelease(path, fi->fh);
    }
    CHECK_AND_RETURN_RET_LOG(err == 0, -ENOENT, "Release: DoRelease failed, path = %{public}s", path);
    return E_OK;
}

static int Create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_CREATE, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        int32_t err = MediaFuseManager::GetInstance().DoHdcCreate(path, mode, fi);
        CHECK_AND_RETURN_RET_LOG(err == 0, err, "Create file failed, path = %{private}s", path);
    }
    return E_OK;
}

static int Unlink(const char *path)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_UNLINK, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        int32_t err = MediaFuseManager::GetInstance().DoHdcUnlink(path);
        CHECK_AND_RETURN_RET_LOG(err == 0, -ENOENT, "Unlink: DoHdcUnlink failed, path = %{public}s", path);
    }
    return E_OK;
}

static int OpenDir(const char *path, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_OPENDIR, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);
    return E_OK;
}

static int ReadDir(const char *path, void *buf, fuse_fill_dir_t fullDir, off_t offset,
	struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_READDIR, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);

    if ((ctx->uid == USER_AND_GROUP_ID && ctx->gid == USER_AND_GROUP_ID) || (ctx->uid == 0 && ctx->gid == 0)) {
        int32_t err = MediaFuseManager::GetInstance().DoHdcReadDir(path, buf, fullDir, FUSE_READDIR_PLUS);
        CHECK_AND_RETURN_RET_LOG(err == 0, -ENOENT, "DoHdcReadDir failed, path = %{public}s", path);
    }
    return E_OK;
}

static int ReleaseDir(const char *path, struct fuse_file_info *fi)
{
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, -ENOENT, "get file context failed");
    DfxTimer dfxTimer(
        DfxType::FUSE_RELEASEDIR, static_cast<int32_t>(OperationObject::FILESYSTEM_PHOTO), COMMON_TIME_OUT, true);
    dfxTimer.SetCallerUid(ctx->uid);
    return E_OK;
}

static const struct fuse_operations high_ops = {
    .getattr    = GetAttr,
    .open       = Open,
    .read       = Read,
    .write      = Write,
    .release    = Release,
    .create     = Create,
    .opendir    = OpenDir,
    .readdir    = ReadDir,
    .releasedir = ReleaseDir,
    .unlink     = Unlink,
};

int32_t MediaFuseDaemon::StartFuse()
{
    int ret = E_OK;

    bool expect = false;
    CHECK_AND_RETURN_RET_LOG(isRunning_.compare_exchange_strong(expect, true), E_FAIL,
        "Fuse daemon is already running");

    std::thread([this]() {
        DaemonThread();
    }).detach();

    return ret;
}

void MediaFuseDaemon::DaemonThread()
{
    struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    struct fuse *fuse_default = nullptr;
    struct fuse_loop_config *loop_config = nullptr;
    string name("mediaFuseDaemon");
    pthread_setname_np(pthread_self(), name.c_str());
    do {
        CHECK_AND_BREAK_ERR_LOG(!fuse_opt_add_arg(&args, "-odebug"), "fuse_opt_add_arg failed");
        fuse_set_log_func([](enum fuse_log_level level, const char *fmt, va_list ap) {
            char *str = nullptr;
            CHECK_AND_RETURN_LOG(vasprintf(&str, fmt, ap) >= 0, "FUSE: log failed");
            MEDIA_ERR_LOG("FUSE: %{public}s", str);
            free(str);
        });

        fuse_default = fuse_new(&args, &high_ops, sizeof(high_ops), nullptr);
        CHECK_AND_BREAK_ERR_LOG(fuse_default != nullptr, "fuse_new failed");
        CHECK_AND_BREAK_ERR_LOG(fuse_mount(fuse_default, mountpoint_.c_str()) == 0,
            "fuse_mount failed, mountpoint_ = %{private}s", mountpoint_.c_str());

        loop_config = fuse_loop_cfg_create();
        CHECK_AND_BREAK_ERR_LOG(loop_config != nullptr, "fuse_loop_cfg_create failed");
        fuse_loop_cfg_set_max_threads(loop_config, FUSE_CFG_MAX_THREADS);
        MEDIA_INFO_LOG("Starting fuse ...");
        fuse_loop_mt(fuse_default, loop_config);
        MEDIA_INFO_LOG("Ending fuse ...");
    } while (false);

    fuse_opt_free_args(&args);
    if (loop_config) {
        fuse_loop_cfg_destroy(loop_config);
    }
    if (fuse_default) {
        fuse_unmount(fuse_default);
        fuse_destroy(fuse_default);
    }
    MEDIA_INFO_LOG("Ended fuse");
}
// LCOV_EXCL_STOP
} // namespace Media
} // namespace OHOS