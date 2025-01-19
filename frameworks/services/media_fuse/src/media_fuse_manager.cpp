/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaFuseManager"
#include "media_fuse_manager.h"

#include <fcntl.h>
#define FUSE_USE_VERSION 34
#include <fuse.h>
#include "dfx_const.h"
#include "dfx_reporter.h"
#include "iservice_registry.h"
#include "media_fuse_daemon.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "os_account_manager.h"
#include "storage_manager_proxy.h"
#include "system_ability_definition.h"
#include "medialibrary_data_manager.h"
#include "media_column.h"
#include "media_privacy_manager.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "rdb_utils.h"
#include "permission_utils.h"
#include "abs_permission_handler.h"
#include "read_write_permission_handler.h"
#include "grant_permission_handler.h"
#include "ipc_skeleton.h"
#include "permission_used_type.h"
#include "medialibrary_object_utils.h"
#include "media_file_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
using namespace std;

const std::string FUSE_ROOT_MEDIA_DIR = "/storage/cloud/files/Photo";
const int32_t URI_SLASH_NUM_API9 = 2;
const int32_t URI_SLASH_NUM_API10 = 4;
const int32_t FUSE_VIRTUAL_ID_DIVIDER = 5;
const int32_t FUSE_PHOTO_VIRTUAL_IDENTIFIER = 4;
const int32_t BASE_USER_RANGE = 200000;
static set<int> readPermSet{0, 1, 3, 4};
static set<int> writePermSet{2, 3, 4};
static const map<uint32_t, string> MEDIA_OPEN_MODE_MAP = {
    { O_RDONLY, MEDIA_FILEMODE_READONLY },
    { O_WRONLY, MEDIA_FILEMODE_WRITEONLY },
    { O_RDWR, MEDIA_FILEMODE_READWRITE },
    { O_WRONLY | O_TRUNC, MEDIA_FILEMODE_WRITETRUNCATE },
    { O_WRONLY | O_APPEND, MEDIA_FILEMODE_WRITEAPPEND },
    { O_RDWR | O_TRUNC, MEDIA_FILEMODE_READWRITETRUNCATE },
    { O_RDWR | O_APPEND, MEDIA_FILEMODE_READWRITEAPPEND },
};

MediafusePermCheckInfo::MediafusePermCheckInfo(const string &filePath, const string &mode, const string &fileId,
    const string &appId, const int32_t &uid)
    : filePath_(filePath), mode_(mode), fileId_(fileId), appId_(appId), uid_(uid)
{}

MediaFuseManager &MediaFuseManager::GetInstance()
{
    static MediaFuseManager instance;
    return instance;
}

void MediaFuseManager::Start()
{
    int32_t ret = E_OK;
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();

    CHECK_AND_RETURN_INFO_LOG(fuseDaemon_ == nullptr, "Fuse daemon already started");

    std::string mountpoint;
    ret = MountFuse(mountpoint);
    if (ret != E_OK) {
        DfxReporter::ReportStartResult(DfxType::START_MOUNT_FUSE_FAIL, ret, startTime);
        MEDIA_ERR_LOG("MountFuse failed");
        return;
    }

    MEDIA_INFO_LOG("Mount fuse successfully, mountpoint = %{public}s", mountpoint.c_str());
    fuseDaemon_ = std::make_shared<MediaFuseDaemon>(mountpoint);
    ret = fuseDaemon_->StartFuse();
    if (ret != E_OK) {
        DfxReporter::ReportStartResult(DfxType::START_FUSE_DAEMON_FAIL, ret, startTime);
        MEDIA_INFO_LOG("Start fuse daemon failed");
        UMountFuse();
    }
}

void MediaFuseManager::Stop()
{
    MEDIA_INFO_LOG("Stop finished successfully");
}

static int32_t countSubString(const string &uri, const string &substr)
{
    int32_t count = 0;
    size_t start = 0;
    while ((start = uri.find(substr, start)) != string::npos) {
        count++;
        start += substr.length();
    }
    return count;
}

static bool IsFullUri(const string &uri)
{
    bool cond = ((uri.find("/Photo") == 0) && (countSubString(uri, "/") == URI_SLASH_NUM_API10));
    CHECK_AND_RETURN_RET(!cond, true);
    cond = (uri.find("/image") == 0) && (countSubString(uri, "/") == URI_SLASH_NUM_API9);
    CHECK_AND_RETURN_RET(!cond, true);
    return false;
}

static int32_t GetFileIdFromUri(string &fileId, const string &uri)
{
    string tmpPath;
    uint32_t pos;
    int32_t virtualId;
    /* uri = "/Photo/fileid/filename/displayname.jpg" */
    if (uri.find("/Photo") == 0) {
        /* tmppath = "fileid/filename/displayname.jpg" */
        tmpPath = uri.substr(strlen("/Photo/"));
        /* get fileid end pos */
        pos = tmpPath.find("/");
        /* get fileid */
        fileId = tmpPath.substr(0, pos);
    } else if (uri.find("/image") == 0) {
        tmpPath = uri.substr(strlen("/image/"));
        CHECK_AND_RETURN_RET(!tmpPath.empty(), E_ERR);
        CHECK_AND_RETURN_RET(all_of(tmpPath.begin(), tmpPath.end(), ::isdigit), E_ERR);
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsValidInteger(tmpPath), E_ERR, "virtual id invalid");
        virtualId = stoi(tmpPath);
        bool cond = ((virtualId + FUSE_PHOTO_VIRTUAL_IDENTIFIER) % FUSE_VIRTUAL_ID_DIVIDER == 0);
        CHECK_AND_RETURN_RET_LOG(cond, E_ERR, "virtual id err");
        fileId = to_string((virtualId + FUSE_PHOTO_VIRTUAL_IDENTIFIER) / FUSE_VIRTUAL_ID_DIVIDER);
    } else {
        MEDIA_ERR_LOG("uri err");
        return E_ERR;
    }
    return E_SUCCESS;
}

static int32_t GetPathFromFileId(string &filePath, const string &fileId)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_ID, fileId);
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));

    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_FILE_PATH);
    columns.push_back(MediaColumn::MEDIA_DATE_TRASHED);
    columns.push_back(MediaColumn::MEDIA_HIDDEN);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    int32_t numRows = 0;
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to get rslt");
        return E_ERR;
    }
    int32_t ret = resultSet->GetRowCount(numRows);
    if ((ret != NativeRdb::E_OK) || (numRows <= 0)) {
        MEDIA_ERR_LOG("Failed to get filePath");
        return E_ERR;
    }
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        filePath = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_FILE_PATH);
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoGetAttr(const char *path, struct stat *stbuf)
{
    string fileId;
    string target = path;
#ifdef MEDIALIBRARY_EMULATOR
    bool cond = (path == nullptr || strlen(path) == 0 ||
        ((target.find("/Photo") != 0) && (target.find("/image") != 0) && (target != "/")));
#else
    bool cond = (path == nullptr || strlen(path) == 0 ||
        ((target.find("/Photo") != 0) && (target.find("/image") != 0)));
#endif
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Invalid path, %{private}s", path == nullptr ? "null" : path);
    int32_t ret;
    if (IsFullUri(target) == false) {
        ret = lstat(FUSE_ROOT_MEDIA_DIR.c_str(), stbuf);
    } else {
        ret = GetFileIdFromUri(fileId, path);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "get attr fileid fail");
        ret = GetPathFromFileId(target, fileId);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "get attr path fail");
        ret = lstat(target.c_str(), stbuf);
    }
    stbuf->st_mode = stbuf->st_mode | 0x6;
    MEDIA_DEBUG_LOG("get attr succ");
    return ret;
}

static int32_t WrCheckPermission(const string &filePath, const string &mode,
    const uid_t &uid, AccessTokenID &tokenCaller)
{
    vector<string> perms;
    if (mode.find("r") != string::npos) {
        perms.push_back(PERM_READ_IMAGEVIDEO);
    }
    if (mode.find("w") != string::npos) {
        perms.push_back(PERM_WRITE_IMAGEVIDEO);
    }
    return PermissionUtils::CheckPhotoCallerPermission(perms, uid, tokenCaller)? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t DbCheckPermission(const string &filePath, const string &mode, const string &fileId,
    const string &appId, const AccessTokenID &tokenCaller)
{
    if (appId.empty() || fileId.empty() || (tokenCaller == INVALID_TOKENID)) {
        MEDIA_ERR_LOG("invalid input");
        return E_PERMISSION_DENIED;
    }
    NativeRdb::RdbPredicates rdbPredicate(TABLE_PERMISSION);
    rdbPredicate.EqualTo("file_id", fileId);
    rdbPredicate.And()->BeginWrap()->EqualTo("appid", appId)
        ->Or()->EqualTo("target_tokenId", to_string(tokenCaller))->EndWrap();
    vector<string> columns;
    columns.push_back(FIELD_PERMISSION_TYPE);
    columns.push_back("file_id");
    columns.push_back("appid");
    columns.push_back("target_tokenId");
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    int32_t permissionType = 0;
    int32_t numRows = 0;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_PERMISSION_DENIED, "Failed to get permission type");
    int32_t ret = resultSet->GetRowCount(numRows);
    bool cond = ((ret != NativeRdb::E_OK) || (numRows <= 0));
    CHECK_AND_RETURN_RET_LOG(!cond, E_PERMISSION_DENIED, "Failed to get permission type");
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        permissionType = MediaLibraryRdbStore::GetInt(resultSet, FIELD_PERMISSION_TYPE);
        MEDIA_INFO_LOG("get permissionType %{public}d", permissionType);
    }
    cond = ((mode.find("r") != string::npos) && (readPermSet.count(permissionType) == 0));
    CHECK_AND_RETURN_RET(!cond, E_PERMISSION_DENIED);
    cond = ((mode.find("w") != string::npos) && (writePermSet.count(permissionType) == 0));
    CHECK_AND_RETURN_RET(!cond, E_PERMISSION_DENIED);
    return E_SUCCESS;
}

int32_t MediafusePermCheckInfo::CheckPermission(uint32_t &tokenCaller)
{
    int err = WrCheckPermission(filePath_, mode_, uid_, tokenCaller);
    bool rslt;
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("wr check succ %{public}d", tokenCaller);
        return true;
    }
    err = DbCheckPermission(filePath_, mode_, fileId_, appId_, tokenCaller);
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("db check succ %{public}d", tokenCaller);
        rslt = true;
    } else {
        rslt = false;
    }
    if (mode_.find("r") != string::npos) {
        PermissionUtils::CollectPermissionInfo(PERM_READ_IMAGEVIDEO, rslt,
            PermissionUsedTypeValue::PICKER_TYPE, uid_);
    }
    if (mode_.find("w") != string::npos) {
        PermissionUtils::CollectPermissionInfo(PERM_WRITE_IMAGEVIDEO, rslt,
            PermissionUsedTypeValue::PICKER_TYPE, uid_);
    }
    return rslt;
}

static int32_t OpenFile(const string &filePath, const string &fileId, const string &mode)
{
    MEDIA_DEBUG_LOG("fuse open file");
    fuse_context *ctx = fuse_get_context();
    uid_t uid = ctx->uid;
    string bundleName;
    AccessTokenID tokenCaller = INVALID_TOKENID;
    PermissionUtils::GetClientBundle(uid, bundleName);
    string appId = PermissionUtils::GetAppIdByBundleName(bundleName, uid);
    class MediafusePermCheckInfo info(filePath, mode, fileId, appId, uid);
    int32_t permGranted = info.CheckPermission(tokenCaller);
    if (permGranted == false) {
        return E_ERR;
    }
    return MediaPrivacyManager(filePath, mode, fileId, appId, bundleName, uid, tokenCaller).Open();
}

int32_t MediaFuseManager::DoOpen(const char *path, int flags, int &fd)
{
    uint32_t realFlag = static_cast<uint32_t>(flags) & (O_RDONLY | O_WRONLY | O_RDWR | O_TRUNC | O_APPEND);
    string fileId;
    string target;
    GetFileIdFromUri(fileId, path);
    GetPathFromFileId(target, fileId);
    fd = OpenFile(target, fileId, MEDIA_OPEN_MODE_MAP.at(realFlag));
    if (fd < 0) {
        MEDIA_ERR_LOG("Open failed, path = %{private}s, errno = %{public}d", target.c_str(), errno);
        return E_ERR;
    }
    return 0;
}

int32_t MediaFuseManager::DoRelease(const char *path, const int &fd)
{
    string fileId;
    string filePath;
    GetFileIdFromUri(fileId, path);
    GetPathFromFileId(filePath, fileId);
    if (fd >= 0) {
        close(fd);
        MediaLibraryObjectUtils::ScanFileAsync(filePath, fileId, MediaLibraryApi::API_10);
        MEDIA_DEBUG_LOG("fuse close file succ");
        return E_OK;
    } else {
        MEDIA_ERR_LOG("fuse close file fail");
        return E_ERR;
    }
}

int32_t MediaFuseManager::MountFuse(std::string &mountpoint)
{
    int devFd = -1;
    // get user id
    int32_t userId =  getuid() / BASE_USER_RANGE;

    // mount fuse
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, E_FAIL, "Get system ability mgr failed.");

    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, E_FAIL, "GetSystemAbility Service Failed.");

    sptr<StorageManager::IStorageManager> proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    int32_t err = proxy_->MountMediaFuse(userId, devFd);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "Mount failed for media fuse daemon, err = %{public}d", err);

    mountpoint = "/dev/fd/" + std::to_string(devFd);
    return E_OK;
}

int32_t MediaFuseManager::UMountFuse()
{
    // get user id
    int32_t userId =  getuid() / BASE_USER_RANGE;

    // umount fuse
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    sptr<StorageManager::IStorageManager> proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    int32_t err = proxy_->UMountMediaFuse(userId);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err,
        "UMount failed for media fuse daemon, err = %{public}d", err);
    return E_OK;
}
} // namespace Media
} // namespace OHOS

