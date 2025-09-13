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

#define MLOG_TAG "MediaFuseManager"
#include "media_fuse_manager.h"

#include <fcntl.h>
#define FUSE_USE_VERSION 34
#include <fuse.h>
#include <sys/utsname.h>
#include "dfx_const.h"
#include "dfx_manager.h"
#include "dfx_reporter.h"
#include "iservice_registry.h"
#include "media_fuse_daemon.h"
#include "media_fuse_hdc_operations.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "os_account_manager.h"
#include "storage_manager_proxy.h"
#include "system_ability_definition.h"
#include "medialibrary_data_manager.h"
#include "media_column.h"
#include "media_privacy_manager.h"
#include "media_visit_count_manager.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "rdb_utils.h"
#include "permission_utils.h"
#include "abs_permission_handler.h"
#include "read_write_permission_handler.h"
#include "grant_permission_handler.h"
#include "heif_transcoding_check_utils.h"
#include "ipc_skeleton.h"
#include "permission_used_type.h"
#include "medialibrary_object_utils.h"
#include "media_file_utils.h"
#include "media_app_uri_permission_column.h"
#include "medialibrary_ptp_operations.h"
#include "medialibrary_photo_operations.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
using namespace std;

const std::string FUSE_ROOT_MEDIA_DIR = "/storage/cloud/files/Photo";
const std::string FUSE_OPEN_PHOTO_PRE = "/Photo";
const int32_t URI_SLASH_NUM_API9 = 2;
const int32_t URI_SLASH_NUM_API10 = 4;
const int32_t FUSE_VIRTUAL_ID_DIVIDER = 5;
const int32_t FUSE_PHOTO_VIRTUAL_IDENTIFIER = 4;
const int32_t BASE_USER_RANGE = 200000;
static constexpr int32_t HDC_FIRST_ARGS = 1;
static constexpr int32_t HDC_SECOND_ARGS = 2;
static constexpr int32_t HDC_THIRD_ARGS = 3;
static const map<uint32_t, string> MEDIA_OPEN_MODE_MAP = {
    { O_RDONLY, MEDIA_FILEMODE_READONLY },
    { O_WRONLY, MEDIA_FILEMODE_WRITEONLY },
    { O_RDWR, MEDIA_FILEMODE_READWRITE },
    { O_WRONLY | O_TRUNC, MEDIA_FILEMODE_WRITETRUNCATE },
    { O_WRONLY | O_APPEND, MEDIA_FILEMODE_WRITEAPPEND },
    { O_RDWR | O_TRUNC, MEDIA_FILEMODE_READWRITETRUNCATE },
    { O_RDWR | O_APPEND, MEDIA_FILEMODE_READWRITEAPPEND },
};
std::map<int, time_t> MEDIA_OPEN_WRITE_MAP;
std::map<std::string, bool> MEDIA_CREATE_WRITE_MAP;

MediafusePermCheckInfo::MediafusePermCheckInfo(const string &filePath, const string &mode, const string &fileId,
    const string &appId, const int32_t &uid)
    : filePath_(filePath), mode_(mode), fileId_(fileId), appId_(appId), uid_(uid)
{}

MediaFuseManager &MediaFuseManager::GetInstance()
{
    static MediaFuseManager instance;
    return instance;
}

bool MediaFuseManager::CheckDeviceInLinux()
{
    struct utsname uts;
    if (uname(&uts) == -1) {
        MEDIA_INFO_LOG("uname get failed");
        return false;
    }
    if (strcmp(uts.sysname, "Linux") == 0) {
        MEDIA_INFO_LOG("uname system is linux");
        return true;
    }
    return false;
}

void MediaFuseManager::Start()
{
    int32_t ret = E_OK;
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();

    CHECK_AND_RETURN_INFO_LOG(fuseDaemon_ == nullptr, "Fuse daemon already started");

    /* init current device is in linux or not */
    isInLinux_ = CheckDeviceInLinux();

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
    bool cond;
    if (isInLinux_) {
        cond = (path == nullptr || strlen(path) == 0 ||
            ((target.find("/Photo") != 0) && (target.find("/image") != 0) && (target != "/")));
    } else {
        cond = (path == nullptr || strlen(path) == 0 ||
            ((target.find("/Photo") != 0) && (target.find("/image") != 0)));
    }

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

static bool CheckPermissionType(const vector<int32_t> currentTypes, const set<int32_t> targetTypes)
{
    for (int32_t type : currentTypes) {
        if (targetTypes.count(type) > 0) {
            return true;
        }
    }
    return false;
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
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_PERMISSION_DENIED, "Failed to get permission type");
    vector<int32_t> permissionTypes;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t permissionType = MediaLibraryRdbStore::GetInt(resultSet, FIELD_PERMISSION_TYPE);
        permissionTypes.push_back(permissionType);
        MEDIA_INFO_LOG("get permissionType %{public}d", permissionType);
    }
    bool cond = ((mode.find("r") != string::npos) &&
        (!CheckPermissionType(permissionTypes, AppUriPermissionColumn::PERMISSION_TYPE_READ)));
    CHECK_AND_RETURN_RET(!cond, E_PERMISSION_DENIED);
    cond = ((mode.find("w") != string::npos) &&
        (!CheckPermissionType(permissionTypes, AppUriPermissionColumn::PERMISSION_TYPE_WRITE)));
    CHECK_AND_RETURN_RET(!cond, E_PERMISSION_DENIED);
    return E_SUCCESS;
}

int32_t MediafusePermCheckInfo::CheckPermission(uint32_t &tokenCaller)
{
    int err = WrCheckPermission(filePath_, mode_, uid_, tokenCaller);
    bool rslt;
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("wr check succ");
        return true;
    }
    err = DbCheckPermission(filePath_, mode_, fileId_, appId_, tokenCaller);
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("db check succ");
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

static int32_t GetCompatibleModeFromFileId(int32_t &compatibleMode, const string &fileId)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_ID, fileId);

    vector<string> columns;
    columns.push_back(PhotoColumn::PHOTO_EXIST_COMPATIBLE_DUPLICATE);
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
        compatibleMode = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::PHOTO_EXIST_COMPATIBLE_DUPLICATE);
    }
    return E_SUCCESS;
}

static int32_t GetTranscodeUri(string &filePath, const string &bundleName, const string &fileId, const string &mode)
{
    if (MediaFileUtils::GetExtensionFromPath(filePath) != "heif" &&
        MediaFileUtils::GetExtensionFromPath(filePath) != "heic") {
        MEDIA_INFO_LOG("Display name is not heif, filePath: %{private}s", filePath.c_str());
        return E_INNER_FAIL;
    }
    CHECK_AND_RETURN_RET_LOG(mode == MEDIA_FILEMODE_READONLY, E_INNER_FAIL,
        "mode is not read only, filePath: %{private}s", filePath.c_str());
    CHECK_AND_RETURN_RET_LOG(HeifTranscodingCheckUtils::CanSupportedCompatibleDuplicate(bundleName), E_INNER_FAIL,
        "Get client bundle name failed, filePath: %{private}s", filePath.c_str());
    int32_t compatibleMode = 0;
    CHECK_AND_RETURN_RET_LOG(GetCompatibleModeFromFileId(compatibleMode, fileId), E_INNER_FAIL,
        "Get compatible mode failed, fileId: %{private}s", fileId.c_str());
    CHECK_AND_RETURN_RET_LOG(compatibleMode != 0, E_INNER_FAIL,
        "Is not have transcode file, filePath: %{private}s", filePath.c_str());
    string path = MediaLibraryAssetOperations::GetEditDataDirPath(filePath);
    CHECK_AND_RETURN_RET_LOG(!path.empty(), E_INNER_FAIL,
        "Get edit data dir path failed, filePath: %{private}s", filePath.c_str());
    MEDIA_INFO_LOG("GetTranscodeUri path: %{private}s", path.c_str());
    string tempPath = path + "/transcode.jpg";
    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::IsFileExists((tempPath)), E_INNER_FAIL, "transcode.jpg is not exist");
    filePath = tempPath;
    return E_OK;
}

static int32_t OpenFile(const string &filePath, const string &fileId, const string &mode)
{
    MEDIA_DEBUG_LOG("fuse open file");
    fuse_context *ctx = fuse_get_context();
    CHECK_AND_RETURN_RET_LOG(ctx != nullptr, E_INNER_FAIL, "fuse_get_context returned nullptr");
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
    string path = filePath;
    int32_t err = GetTranscodeUri(path, bundleName, fileId, mode);
    int32_t ret = MediaPrivacyManager(path, mode, fileId, appId, bundleName, uid, tokenCaller).Open();
    if (err == 0 && ret >= 0) {
        MEDIA_INFO_LOG("libc open transcode file success");
        auto dfxManager = DfxManager::GetInstance();
        CHECK_AND_RETURN_RET_LOG(dfxManager != nullptr, E_INNER_FAIL, "DfxManager::GetInstance() returned nullptr");
        dfxManager->HandleTranscodeAccessTime(ACCESS_LIBC);
    }
    return ret;
}

static int32_t HasTransCodeFile(const string &filePath, const string &fileId)
{
    if (MediaFileUtils::GetExtensionFromPath(filePath) != "heif" &&
        MediaFileUtils::GetExtensionFromPath(filePath) != "heic") {
        MEDIA_INFO_LOG("Display name is not heif, filePath: %{private}s", filePath.c_str());
        return E_ERR;
    }
    int32_t compatibleMode = 0;
    if (!GetCompatibleModeFromFileId(compatibleMode, fileId)) {
        MEDIA_ERR_LOG("Get compatible mode failed, fileId: %{public}s", fileId.c_str());
        return E_ERR;
    }
    return E_OK;
}

static int32_t GetFileMtime(const string &filePath, time_t &mtime)
{
    struct stat statInfo {};
    if (stat(filePath.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("Get file mtime failed, path = %{private}s", filePath.c_str());
        return E_ERR;
    }
    mtime = statInfo.st_mtime;
    return E_OK;
}

int32_t MediaFuseManager::DoOpen(const char *path, int flags, int &fd)
{
    uint32_t realFlag = static_cast<uint32_t>(flags) & (O_RDONLY | O_WRONLY | O_RDWR | O_TRUNC | O_APPEND);
    string fileId;
    string target;
    if (MEDIA_OPEN_MODE_MAP.find(realFlag) == MEDIA_OPEN_MODE_MAP.end()) {
        MEDIA_ERR_LOG("Open mode err, flag = %{public}u", realFlag);
        return E_ERR;
    }
    GetFileIdFromUri(fileId, path);
    GetPathFromFileId(target, fileId);
    if (std::string(path).find(FUSE_OPEN_PHOTO_PRE) != std::string::npos) {
        MEDIA_DEBUG_LOG("MediaFuseManager::DoOpen AddVisitCount fileId[%{public}s]", fileId.c_str());
        MediaVisitCountManager::AddVisitCount(MediaVisitCountManager::VisitCountType::PHOTO_FS, fileId);
    }
    fd = OpenFile(target, fileId, MEDIA_OPEN_MODE_MAP.at(realFlag));
    if (fd < 0) {
        MEDIA_ERR_LOG("Open failed, path = %{private}s, errno = %{public}d", target.c_str(), errno);
        return E_ERR;
    }
    time_t mtime = 0;
    if (realFlag == O_RDONLY || HasTransCodeFile(target, fileId) != E_OK || GetFileMtime(target, mtime) != E_OK) {
        return E_OK;
    }
    MEDIA_OPEN_WRITE_MAP.insert(std::make_pair(fd, mtime));
    return 0;
}

int32_t MediaFuseManager::DoRelease(const char *path, const int &fd)
{
    string fileId;
    string filePath;
    GetFileIdFromUri(fileId, path);
    GetPathFromFileId(filePath, fileId);
    if (fd < 0) {
        MEDIA_ERR_LOG("fuse close file fail");
        return E_ERR;
    }
    if (MEDIA_OPEN_WRITE_MAP.find(fd) != MEDIA_OPEN_WRITE_MAP.end()) {
        time_t oldMtime = MEDIA_OPEN_WRITE_MAP[fd];
        MEDIA_OPEN_WRITE_MAP.erase(fd);
        time_t newMtime = 0;
        if (GetFileMtime(filePath, newMtime) != E_OK) {
            MEDIA_ERR_LOG("Get file mtime failed, path = %{private}s", filePath.c_str());
            close(fd);
            return E_ERR;
        }
        if (oldMtime != newMtime) {
            MediaLibraryAssetOperations::DeleteTransCodeInfo(filePath, fileId, __func__);
        }
    }
    close(fd);
    MediaLibraryObjectUtils::ScanFileAsync(filePath, fileId, MediaLibraryApi::API_10);
    MEDIA_DEBUG_LOG("fuse close file succ");
    return E_OK;
}

int32_t MediaFuseManager::MountFuse(std::string &mountpoint)
{
    int devFd = -1;
    // get user id
    int32_t userId =  static_cast<int32_t>(getuid() / BASE_USER_RANGE);

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
    int32_t userId =  static_cast<int32_t>(getuid() / BASE_USER_RANGE);

    // umount fuse
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    sptr<StorageManager::IStorageManager> proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    int32_t err = proxy_->UMountMediaFuse(userId);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err,
        "UMount failed for media fuse daemon, err = %{public}d", err);
    return E_OK;
}

int32_t MediaFuseManager::DoHdcGetAttr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    MEDIA_INFO_LOG("Hdc getattr start, path = %{private}s", path);
    if (fi) {
        return MediaFuseHdcOperations::HandleFstat(fi, stbuf);
    }

    int32_t res = MediaFuseHdcOperations::HandleRootOrPhoto(path, stbuf);
    if (res == E_SUCCESS) {
        return res;
    }

    vector<string> args;
    res = MediaFuseHdcOperations::GetArgs(path, args);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetArgs fail.");
    if (args.size() < HDC_SECOND_ARGS) {
        MEDIA_ERR_LOG("Invalid path.");
        return E_ERR;
    }

    int32_t albumId = -1;
    string localPath;
    if (args.size() == HDC_SECOND_ARGS) {
        int32_t result = MediaFuseHdcOperations::HandlePhotoPath(args[HDC_FIRST_ARGS], albumId, localPath, stbuf);
        if (result != E_SUCCESS) {
            return result;
        }
        return E_SUCCESS;
    }

    if (args.size() > HDC_THIRD_ARGS || !MediaFuseHdcOperations::IsImageOrVideoFile(args[HDC_SECOND_ARGS])) {
        MEDIA_ERR_LOG("Invalid path.");
        return E_ERR;
    }

    res = MediaFuseHdcOperations::HandleFilePath(args, albumId, localPath);
    if (res != E_SUCCESS) {
        return res;
    }

    res = MediaFuseHdcOperations::HandleLstat(localPath, stbuf);
    if (res != E_SUCCESS) {
        return res;
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcOpen(const char *path, int flags, int &fd)
{
    MEDIA_INFO_LOG("hdc open start, path = %{private}s", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }

    string target = path;
    int32_t albumId = -1;
    string filePath;
    string displayName;
    int32_t res = MediaFuseHdcOperations::Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");
    if (filePath.empty()) {
        // handle moving photo mp4
        res = MediaFuseHdcOperations::HandleMovingPhoto(filePath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
        res = MediaFuseHdcOperations::GetPathFromDisplayname(displayName, albumId, filePath);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFromDisplayname fail");
        filePath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(filePath);
    }
    if (flags & (O_CREAT | O_WRONLY)) {
        if (MediaFuseHdcOperations::DeletePhotoByFilePath(filePath) != 0) {
            MEDIA_ERR_LOG("Delete failed");
            return E_ERR;
        }
        MEDIA_CREATE_WRITE_MAP[target] = false;
        res = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
        if (fd <= 0) {
            MEDIA_ERR_LOG("MediaLibraryPhotoOperations::Create failed, path = %{public}s", filePath.c_str());
            return E_ERR;
        }
        MEDIA_CREATE_WRITE_MAP[target] = true;
        return E_SUCCESS;
    }

    string localPath;
    if (MediaFuseHdcOperations::ConvertToLocalPhotoPath(filePath, localPath) != E_SUCCESS) {
        MEDIA_ERR_LOG("ConvertToLocalPhotoPath failed, filePath = %{public}s", filePath.c_str());
        return E_ERR;
    }

    fd = open(localPath.c_str(), flags);
    if (fd < 0) {
        int32_t err = -errno;
        MEDIA_ERR_LOG("Open failed, localPath=%{public}s, errno=%{public}d",
                      localPath.c_str(), err);
        return err;
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcCreate(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    MEDIA_INFO_LOG("hdc create file start, path=%{private}s", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }
    string target = path;
    MEDIA_CREATE_WRITE_MAP[target] = false;

    int32_t albumId = -1;
    string filePath;
    string displayName;
    int32_t res = MediaFuseHdcOperations::Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");

    int32_t fd;
    res = MediaFuseHdcOperations::CreateFd(displayName, albumId, fd);
    if (fd <= 0) {
        MEDIA_ERR_LOG("MediaLibraryPhotoOperations::Create failed, path = %{public}s", filePath.c_str());
        return res;
    }
    fi->fh = static_cast<uint64_t>(fd);
    MEDIA_CREATE_WRITE_MAP[target] = true;
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcRelease(const char *path, const int32_t &fd)
{
    MEDIA_INFO_LOG("hdc release start, path=%{private}s.", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }

    if (fd < 0) {
        MEDIA_ERR_LOG("Invalid fd (negative), path=%{private}s, fd=%{private}d", path, fd);
        return -EBADF;
    }

    if (close(fd) == -1) {
        MEDIA_ERR_LOG("Close fd failed, path=%{private}s, fd=%d, errno=%{public}d", path, fd, errno);
        return -errno;
    }

    string target = path;
    if (MEDIA_CREATE_WRITE_MAP.find(target) != MEDIA_CREATE_WRITE_MAP.end()) {
        if (MEDIA_CREATE_WRITE_MAP[target]) {
            int32_t res = MediaFuseHdcOperations::ScanFileByPath(target);
            MEDIA_CREATE_WRITE_MAP.erase(target);
            return res;
        } else {
            MEDIA_ERR_LOG("DoHdcCreate failed.");
            MEDIA_CREATE_WRITE_MAP.erase(target);
            return E_ERR;
        }
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcUnlink(const char *path)
{
    MEDIA_INFO_LOG("Unlink file start, path=%{private}s.", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return E_ERR;
    }

    string target = path;
    int32_t albumId = -1;
    string filePath;
    string displayName;
    int32_t res = MediaFuseHdcOperations::Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");

    string fileId;
    if (filePath.empty()) {
        res = MediaFuseHdcOperations::HandleMovingPhoto(filePath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
        res = MediaFuseHdcOperations::GetPathFromDisplayname(displayName, albumId, filePath);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFromDisplayname fail");
    }
    int ret = MediaFuseHdcOperations::DeletePhotoByFilePath(filePath);
    if (ret != 0) {
        MEDIA_ERR_LOG("Unlink failed");
        return ret;
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcReadDir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
    enum fuse_readdir_flags flags)
{
    MEDIA_INFO_LOG("hdc readdir start, path=%{private}s.", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }

    string target = path;
    if (target == FUSE_OPEN_PHOTO_PRE) {
        return MediaFuseHdcOperations::ReadPhotoRootDir(buf, filler, offset);
    }

    if (target.find(FUSE_OPEN_PHOTO_PRE + "/") == 0) {
        return MediaFuseHdcOperations::ReadAlbumDir(target, buf, filler, offset);
    }

    MEDIA_ERR_LOG("Invalid path format: %{public}s", path);
    return -EINVAL;
}
} // namespace Media
} // namespace OHOS