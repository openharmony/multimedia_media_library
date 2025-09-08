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
const std::string FUSE_LOCAL_MEDIA_DIR = "/storage/media/local/files/Photo";
const std::string FUSE_URI_PREFIX = "file://media";
const std::string HIDDEN_ALBUM = ".hiddenAlbum";
const std::string PHOTO_EXTENSION = "jpg";
const std::string VIDEO_EXTENSION = "mp4";
const std::string FIXED_PHOTO_ALBUM = "DeveloperAlbum";
const int32_t URI_SLASH_NUM_API9 = 2;
const int32_t URI_SLASH_NUM_API10 = 4;
const int32_t FUSE_VIRTUAL_ID_DIVIDER = 5;
const int32_t FUSE_PHOTO_VIRTUAL_IDENTIFIER = 4;
const int32_t BASE_USER_RANGE = 200000;
static constexpr int32_t HDC_FIRST_ARGS = 1;
static constexpr int32_t HDC_SECOND_ARGS = 2;
static constexpr int32_t HDC_THIRD_ARGS = 3;
static constexpr uid_t CUSTOM_UID = 1008;
static constexpr mode_t DIR_PERMISSION = 0777;
static constexpr mode_t FILE_PERMISSION = 0664;
static constexpr off_t DIR_DEFAULT_SIZE = 3440;
static constexpr int64_t NANOSECONDS_PER_SECOND = 1000000000000LL;
static constexpr int64_t MILLISECONDS_PER_SECOND = 1000LL;
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

static time_t GetAlbumMTime(const shared_ptr<NativeRdb::ResultSet>& resultSet)
{
    int64_t dateModified = GetInt64Val(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, resultSet);
    int64_t dateAdded = GetInt64Val(PhotoAlbumColumns::ALBUM_DATE_ADDED, resultSet);
    int64_t mtimeRaw = (dateModified > 0) ? dateModified : dateAdded;
    if (mtimeRaw > NANOSECONDS_PER_SECOND) {
        mtimeRaw /= MILLISECONDS_PER_SECOND;
    }
    return (mtimeRaw > 0) ? static_cast<time_t>(mtimeRaw) : time(nullptr);
}

static void FillDirStat(struct stat *stbuf, time_t mtime = 0)
{
    if (!stbuf) {
        return;
    }

    *stbuf = (struct stat) {
        .st_mode = S_IFDIR | DIR_PERMISSION,
        .st_nlink = 2,
        .st_uid = CUSTOM_UID,
        .st_gid = CUSTOM_UID,
        .st_size = DIR_DEFAULT_SIZE,
    };
    stbuf->st_mtime = mtime ? mtime : time(nullptr);
    stbuf->st_ctime = stbuf->st_mtime;
    stbuf->st_atime = stbuf->st_mtime;
}

static int32_t GetArgs(const string &path, vector<string> &parts)
{
    if (path.find(FUSE_OPEN_PHOTO_PRE) != 0) {
        MEDIA_ERR_LOG("GetArgs inputPath err.");
        return E_ERR;
    }

    stringstream ss(path);
    string part;
    while (getline(ss, part, '/')) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    return E_SUCCESS;
}

static bool IsImageOrVideoFile(const string &fileName)
{
    auto mediaType = MediaFileUtils::GetMediaType(fileName);
    return (mediaType == Media::MediaType::MEDIA_TYPE_IMAGE) ||
        (mediaType == Media::MediaType::MEDIA_TYPE_VIDEO);
}

static int32_t GetPathFormDisplayname(const string &displayName, int albumId, string &filePath)
{
    if (displayName.empty()) {
        MEDIA_ERR_LOG("Displayname is empty.");
        return E_ERR;
    }

    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    rdbPredicate.And()->EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    vector<string> positions = {to_string(1), to_string(3)};
    rdbPredicate.And()->In(PhotoColumn::PHOTO_POSITION, positions);

    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_FILE_PATH);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to get filePath from db");
        return E_ERR;
    }

    filePath = "";
    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        filePath = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_FILE_PATH);
    }
    MEDIA_INFO_LOG("get filePath from db, filePath = %{private}s", filePath.c_str());
    return E_SUCCESS;
}

static int32_t GetAlbumIdFromAlbumName(const string &name, int32_t &albumId)
{
    if (name.empty()) {
        MEDIA_ERR_LOG("AlbumName is empty.");
        return E_ERR;
    }

    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_NAME, name);
    rdbPredicate.And()->IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
    rdbPredicate.And()->NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, HIDDEN_ALBUM);

    vector<string> columns;
    columns.push_back(PhotoAlbumColumns::ALBUM_ID);

    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query albumName and id from db");
        return E_ERR;
    }

    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        albumId = MediaLibraryRdbStore::GetInt(resultSet, PhotoAlbumColumns::ALBUM_ID);
        return E_SUCCESS;
    }
    albumId = 0;
    MEDIA_INFO_LOG("get albumId from db, albumId = %{private}d", albumId);
    return E_SUCCESS;
}

static int32_t Parse(const string &path, int32_t &albumId, string &filePath, string &displayName)
{
    vector<string> args;
    int32_t res = GetArgs(path, args);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetArgs fail.");
    if (args.size() < HDC_SECOND_ARGS) {
        MEDIA_ERR_LOG("invalid path.");
        return E_ERR;
    }
    displayName = args[args.size() - 1];

    if (args.size() == HDC_SECOND_ARGS) {
        res = GetAlbumIdFromAlbumName(FIXED_PHOTO_ALBUM, albumId);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetAlbumIdFromAlbumName fail");
    } else {
        res = GetAlbumIdFromAlbumName(args[HDC_FIRST_ARGS], albumId);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetAlbumIdFromAlbumName fail");
    }
    res = GetPathFormDisplayname(displayName, albumId, filePath);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFormDisplayname fail");
    return res;
}

static int32_t ExtractFileNameAndExtension(const string &input, string &outName, string &outExt)
{
    if (input.empty()) {
        return E_ERR;
    }

    string fileName;
    size_t lastSlashPos = input.find_last_of('/');
    if (lastSlashPos == string::npos) {
        fileName = input;
    } else {
        fileName = input.substr(lastSlashPos + 1);
        if (fileName.empty()) {
            return E_ERR;
        }
    }

    size_t lastDotPos = fileName.find_last_of('.');
    if (lastDotPos == string::npos || lastDotPos == 0 || lastDotPos == fileName.length() - 1) {
        outName = fileName;
        outExt = "";
        return E_SUCCESS;
    }

    outName = fileName.substr(0, lastDotPos);
    outExt = fileName.substr(lastDotPos + 1);
    return E_SUCCESS;
}

static bool IsMovingPhoto(int32_t subtype, int32_t effectMode)
{
    return (subtype == static_cast<int32_t>(PhotoSubType::MOVING_PHOTO) ||
        effectMode == static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY));
}

static int32_t HandleMovingPhoto(string &filePath, string &displayName, int32_t albumId)
{
    string title;
    string ext;
    int32_t res = ExtractFileNameAndExtension(displayName, title, ext);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "ExtractFileNameAndExtension fail");
    displayName = title + "." + PHOTO_EXTENSION;

    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_NAME, displayName);
    rdbPredicate.And()->EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
    vector<string> columns = {
        PhotoColumn::PHOTO_SUBTYPE,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE
    };

    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query date from db");
        return E_ERR;
    }

    if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t subtype = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::PHOTO_SUBTYPE);
        int32_t effectMode = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::MOVING_PHOTO_EFFECT_MODE);
        if (IsMovingPhoto(subtype, effectMode)) {
            res = GetPathFormDisplayname(displayName, albumId, filePath);
            CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFormDisplayname fail");
        }
    }
    return res;
}

static int32_t HandleFstat(const struct fuse_file_info *fi, struct stat *stbuf)
{
    int32_t res = fstat(static_cast<int32_t>(fi->fh), stbuf);
    if (res < 0) {
        MEDIA_ERR_LOG("fstat failed, res = %{public}d", res);
        return -errno;
    }
    return E_SUCCESS;
}

static int32_t HandleRootOrPhoto(const char *path, struct stat *stbuf)
{
    if (strcmp(path, "/") == 0 || strcmp(path, "/Photo") == 0) {
        FillDirStat(stbuf);
        return E_SUCCESS;
    }
    return E_ERR;
}

static int32_t HandleDirStat(const int32_t &albumId, struct stat *stbuf)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    rdbPredicate.Limit(1);

    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_DATE_MODIFIED,
        PhotoAlbumColumns::ALBUM_DATE_ADDED
    };

    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query date from db");
        return E_ERR;
    }

    time_t mtime = GetAlbumMTime(resultSet);
    FillDirStat(stbuf, mtime);
    return E_SUCCESS;
}

static int32_t HandleLstat(const string &localPath, struct stat *stbuf)
{
    int32_t res = lstat(localPath.c_str(), stbuf);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR,
        "lstat fail localPath = %{private}s, errno = %{public}d.", localPath.c_str(), errno);
    stbuf->st_mode = stbuf->st_mode | 0x6;
    return E_SUCCESS;
}

static int32_t HandlePhotoPath(const string &inputPath, int32_t &albumId,
    string &localPath, struct stat *stbuf)
{
    int32_t res = -1;
    if (IsImageOrVideoFile(inputPath)) {
        /* /Photo/xxx.jpg || /Photo/xxx.mp4 */
        res = GetAlbumIdFromAlbumName(FIXED_PHOTO_ALBUM, albumId);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetAlbumIdFromAlbumName fail");
        res = GetPathFormDisplayname(inputPath, albumId, localPath);
        CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFormDisplayname fail");
        if (localPath.empty()) {
            MEDIA_ERR_LOG("LocalPath is empty.");
            return -ENOENT;
        }
        return E_SUCCESS;
    }
    /* /Photo/xxx */
    res = GetAlbumIdFromAlbumName(inputPath, albumId);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetAlbumIdFromAlbumName fail");
    if (albumId <= 0) {
        MEDIA_ERR_LOG("not exit album %{public}s.", inputPath.c_str());
        return -ENOENT;
    }
    res = HandleDirStat(albumId, stbuf);
    if (res != E_SUCCESS) {
        MEDIA_ERR_LOG("HandleDirStat fail");
        return res;
    }
    return E_SUCCESS;
}

static int32_t HandleImageFilePath(const vector<string> &args, int32_t &albumId, string &localPath)
{
    int32_t res = GetAlbumIdFromAlbumName(args[HDC_FIRST_ARGS], albumId);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetAlbumIdFromAlbumName fail");
    res = GetPathFormDisplayname(args[HDC_SECOND_ARGS], albumId, localPath);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetPathFormDisplayname fail");

    string displayName = args[HDC_SECOND_ARGS];
    if (localPath.empty()) {
        res = HandleMovingPhoto(localPath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
    }

    if (localPath.empty()) {
        MEDIA_ERR_LOG("Displayname is not exited.");
        return -ENOENT;
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcGetAttr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    MEDIA_INFO_LOG("Hdc getattr start, path = %{private}s", path);
    if (fi) {
        return HandleFstat(fi, stbuf);
    }

    int32_t res = HandleRootOrPhoto(path, stbuf);
    if (res == E_SUCCESS) {
        return res;
    }

    vector<string> args;
    res = GetArgs(path, args);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetArgs fail.");
    if (args.size() < HDC_SECOND_ARGS) {
        MEDIA_ERR_LOG("Invalid path.");
        return E_ERR;
    }

    int32_t albumId = -1;
    string localPath;
    if (args.size() == HDC_SECOND_ARGS) {
        int32_t result = HandlePhotoPath(args[HDC_FIRST_ARGS], albumId, localPath, stbuf);
        if (result != E_SUCCESS) {
            return result;
        }
        return E_SUCCESS;
    }

    if (args.size() > HDC_THIRD_ARGS || !IsImageOrVideoFile(args[HDC_SECOND_ARGS])) {
        MEDIA_ERR_LOG("Invalid path.");
        return E_ERR;
    }

    res = HandleImageFilePath(args, albumId, localPath);
    if (res != E_SUCCESS) {
        return res;
    }

    res = HandleLstat(localPath, stbuf);
    if (res != E_SUCCESS) {
        return res;
    }
    return E_SUCCESS;
}

static int32_t ConvertToLocalPhotoPath(const string &inputPath, string &output)
{
    if (inputPath.find(FUSE_ROOT_MEDIA_DIR) != 0) {
        MEDIA_ERR_LOG("ConvertToLocalPhotoPath inputPath err");
        return E_ERR;
    }
    output = FUSE_LOCAL_MEDIA_DIR + inputPath.substr(FUSE_ROOT_MEDIA_DIR.length());
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
    int32_t res = Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");
    if (filePath.empty()) {
        res = HandleMovingPhoto(filePath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
    }

    string localPath;
    if (ConvertToLocalPhotoPath(filePath, localPath) != E_SUCCESS) {
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

static int32_t CreateFd(const string &displayName, const int32_t &albumId, int32_t &fd)
{
    string title;
    string extension;
    int ret = ExtractFileNameAndExtension(displayName, title, extension);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "ExtractFileNameAndExtension failed.");

    NativeRdb::ValuesBucket assetInfo;
    assetInfo.PutString(ASSET_EXTENTION, extension);
    if (extension == PHOTO_EXTENSION) {
        assetInfo.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    } else if (extension == VIDEO_EXTENSION) {
        assetInfo.PutInt(MediaColumn::MEDIA_TYPE, MEDIA_TYPE_VIDEO);
    }
    assetInfo.PutString(MediaColumn::MEDIA_TITLE, title);
    assetInfo.PutString(MediaColumn::MEDIA_NAME, displayName);
    assetInfo.PutInt(MediaColumn::MEDIA_TIME_PENDING, 0);
    if (albumId == 0) {
        assetInfo.Put(MediaColumn::MEDIA_PACKAGE_NAME, FIXED_PHOTO_ALBUM);
    } else {
        assetInfo.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, MediaLibraryApi::API_10);
    cmd.SetValueBucket(assetInfo);
    ret = MediaLibraryPhotoOperations::Create(cmd);
    if (ret < 0) {
        MEDIA_ERR_LOG("MediaLibraryPhotoOperations::Create failed, ret = %{public}d", ret);
        return E_ERR;
    }

    string fileUriStr = cmd.GetResult();
    Uri uri(fileUriStr);
    MediaLibraryCommand openLivePhotoCmd(uri, Media::OperationType::OPEN);
    fd = MediaLibraryPhotoOperations::Open(openLivePhotoCmd, "w");
    if (fd <= 0) {
        int32_t err = -errno;
        MEDIA_ERR_LOG("Open failed, errno=%{public}d", err);
        return err;
    }
    MEDIA_INFO_LOG("CreateFd success, fd = %{private}d", fd);
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
    int32_t res = Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");

    int32_t fd;
    res = CreateFd(displayName, albumId, fd);
    if (fd <= 0) {
        MEDIA_ERR_LOG("MediaLibraryPhotoOperations::Create failed, path = %{private}s, err = %{public}d",
            filePath.c_str(), errno);
        return -errno;
    }
    fi->fh = static_cast<uint64_t>(fd);
        MEDIA_CREATE_WRITE_MAP[target] = true;
    return E_SUCCESS;
}

static int32_t GetFileIdFromPath(const string &filePath, string &fileId)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_FILE_PATH, filePath);

    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_ID);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to get rslt.");
        return E_ERR;
    }

    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to find row.");
        return E_ERR;
    }
    fileId = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_ID);
    MEDIA_INFO_LOG("get fileId from db, fileId = %{private}s", fileId.c_str());
    return E_SUCCESS;
}

static int32_t UpdatePhotoRdb(const string &displayName, const string &filePath)
{
    string title;
    string ext;
    string fileId;
    int32_t res = ExtractFileNameAndExtension(filePath, title, ext);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "ExtractFileNameAndExtension fail");
    res = GetFileIdFromPath(filePath, fileId);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetFileIdFromPath fail");
    string uri = FUSE_URI_PREFIX + FUSE_OPEN_PHOTO_PRE + "/" + fileId + "/" + title + "/" + displayName;
    MEDIA_INFO_LOG("UpdatePhotoRdb uri = %{private}s", uri.c_str());

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Failed to get rdbStore instance.");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryCommand updatePendingCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    updatePendingCmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, fileId);
    ValuesBucket values;
    int64_t pendingTime = UNCLOSE_FILE_TIMEPENDING;
    values.PutLong(MediaColumn::MEDIA_TIME_PENDING, pendingTime);
    updatePendingCmd.SetValueBucket(values);
    int32_t rowId = 0;
    int32_t result = rdbStore->Update(updatePendingCmd, rowId);
    if (result != NativeRdb::E_OK || rowId <= 0) {
        MEDIA_ERR_LOG("Update File pending failed. Result %{public}d.", result);
        return E_HAS_DB_ERROR;
    }

    MediaLibraryCommand closeCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CLOSE);
    ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);
    closeCmd.SetValueBucket(valuesBucket);
    closeCmd.SetTableName(PhotoColumn::PHOTOS_TABLE);
    int32_t ret = MediaLibraryPhotoOperations::Close(closeCmd);
    if (ret < 0) {
        MEDIA_ERR_LOG("MediaLibraryPhotoOperations::Close failed ret = %{public}d.", ret);
        return E_HAS_DB_ERROR;
    }
    return E_SUCCESS;
}

static int32_t ScanFileByPath(const string &path)
{
    MEDIA_INFO_LOG("hdc write start, path=%{private}s.", path.c_str());
    if (path.empty()) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }

    int32_t albumId = -1;
    string filePath;
    string displayName;
    int32_t res = Parse(path, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");
    if (filePath.empty()) {
        res = HandleMovingPhoto(filePath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
    }

    res = UpdatePhotoRdb(displayName, filePath);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "UpdatePhotoRdb fail");
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
            int32_t res = ScanFileByPath(target);
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
    int32_t res = Parse(target, albumId, filePath, displayName);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "Parse fail");

    string fileId;
    if (filePath.empty()) {
        res = HandleMovingPhoto(filePath, displayName, albumId);
        if (res != E_SUCCESS) {
            MEDIA_ERR_LOG("HandleMovingPhoto fail");
            return res;
        }
    }
    res = GetFileIdFromPath(filePath, fileId);
    CHECK_AND_RETURN_RET_LOG(res == E_SUCCESS, E_ERR, "GetFileIdFromPath fail");

    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.EqualTo(MediaColumn::MEDIA_ID, fileId);
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    int ret = MediaLibraryPtpOperations::DeletePtpPhoto(rdbPredicate);
    if (ret != 0) {
        MEDIA_ERR_LOG("Unlink failed, errno=%{public}d", errno);
        return E_ERR;
    }
    return E_SUCCESS;
}

static int32_t ReadPhotoRootDir(void *buf, fuse_fill_dir_t filler)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.IsNotNull(MEDIA_DATA_DB_ALBUM_NAME);
    rdbPredicate.NotEqualTo(MEDIA_DATA_DB_ALBUM_NAME, HIDDEN_ALBUM);

    vector<string> columns = {
        PhotoAlbumColumns::ALBUM_NAME,
        PhotoAlbumColumns::ALBUM_DATE_ADDED,
        PhotoAlbumColumns::ALBUM_DATE_MODIFIED
    };

    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query albumName and date from db");
        return E_ERR;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string albumName = MediaLibraryRdbStore::GetString(resultSet, PhotoAlbumColumns::ALBUM_NAME);
        time_t mtime = GetAlbumMTime(resultSet);
        struct stat st;
        FillDirStat(&st, mtime);
        off_t nextoff = 0;
        if (filler(buf, albumName.c_str(), &st, nextoff, FUSE_FILL_DIR_PLUS)) {
            break;
        }
    }
    return E_SUCCESS;
}

static void JpgToMp4(const string& displayName, set<string>& fileNames)
{
    size_t dotPos = displayName.find_last_of('.');
    string videoName = (dotPos != string::npos)
        ? displayName.substr(0, dotPos) + "." + VIDEO_EXTENSION
        : displayName + "." + VIDEO_EXTENSION;
    fileNames.insert(videoName);
}

static bool FillDirectoryEntry(void* buf, fuse_fill_dir_t filler, const string& name, const string& fullPath)
{
    struct stat st;
    if (lstat(fullPath.c_str(), &st) == -1) {
        st.st_mode = S_IFREG | FILE_PERMISSION;
        st.st_nlink = 1;
        st.st_uid = CUSTOM_UID;
        st.st_gid = CUSTOM_UID;
        st.st_size = 0;
    }
    off_t nextoff = 0;
    return filler(buf, name.c_str(), &st, nextoff, FUSE_FILL_DIR_PLUS);
}

static shared_ptr<NativeRdb::ResultSet> QueryAlbumPhotos(const int32_t &albumId)
{
    NativeRdb::RdbPredicates photoPred(PhotoColumn::PHOTOS_TABLE);
    photoPred.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
    photoPred.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    photoPred.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));

    vector<string> positions = {to_string(1), to_string(3)};
    photoPred.And()->In(PhotoColumn::PHOTO_POSITION, positions);

    vector<string> columns = {
        MediaColumn::MEDIA_NAME,
        MediaColumn::MEDIA_FILE_PATH,
        PhotoColumn::PHOTO_SUBTYPE,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE
    };
    return MediaLibraryRdbStore::Query(photoPred, columns);
}

static int32_t ReadAlbumDir(const string &inputPath, void* buf, fuse_fill_dir_t filler)
{
    string albumName = inputPath.substr(FUSE_OPEN_PHOTO_PRE.length() + 1);
    int32_t albumId;
    int32_t res = GetAlbumIdFromAlbumName(albumName, albumId);
    if (res != E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to get album ID for: %{public}s", albumName.c_str());
        return res;
    }

    auto resultSet = QueryAlbumPhotos(albumId);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query photos in album");
        return E_ERR;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string displayName = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_NAME);
        int32_t subtype = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::PHOTO_SUBTYPE);
        int32_t effectMode = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::MOVING_PHOTO_EFFECT_MODE);
        string filePath = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_FILE_PATH);

        string localPath;
        if (ConvertToLocalPhotoPath(filePath, localPath) != E_SUCCESS) {
            MEDIA_ERR_LOG("Failed to convert to local path: %{public}s", filePath.c_str());
            continue;
        }

        set<string> fileNames;
        string videoPath;
        fileNames.insert(displayName);
        if (IsMovingPhoto(subtype, effectMode)) {
            videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(localPath);
            JpgToMp4(displayName, fileNames);
        }

        for (const auto& name : fileNames) {
            string fullPath = (name == displayName) ? localPath : videoPath;
            if (FillDirectoryEntry(buf, filler, name, fullPath)) {
                return E_SUCCESS;
            }
        }
    }
    return E_SUCCESS;
}

int32_t MediaFuseManager::DoHdcReadDir(const char *path, void *buf, fuse_fill_dir_t filler,
    enum fuse_readdir_flags flags)
{
    MEDIA_INFO_LOG("hdc readdir start, path=%{private}s.", path);
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path");
        return -EINVAL;
    }

    string target = path;
    if (target == FUSE_OPEN_PHOTO_PRE) {
        return ReadPhotoRootDir(buf, filler);
    }

    if (target.find(FUSE_OPEN_PHOTO_PRE + "/") == 0) {
        return ReadAlbumDir(target, buf, filler);
    }

    MEDIA_ERR_LOG("Invalid path format: %{public}s", path);
    return -EINVAL;
}
} // namespace Media
} // namespace OHOS