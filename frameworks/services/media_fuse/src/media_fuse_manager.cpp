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
#include "medialibrary_bundle_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
using namespace std;

const std::string FUSE_ROOT_MEDIA_DIR = "/storage/cloud/files";
static set<int> readPermSet{0, 1, 3, 4};
static set<int> writePermSet{2, 3, 4};
static const map<int32_t, string> MEDIA_OPEN_MODE_MAP = {
    { O_RDONLY, MEDIA_FILEMODE_READONLY },
    { O_WRONLY, MEDIA_FILEMODE_WRITEONLY },
    { O_RDWR, MEDIA_FILEMODE_READWRITE },
    { O_WRONLY | O_TRUNC, MEDIA_FILEMODE_WRITETRUNCATE },
    { O_WRONLY | O_APPEND, MEDIA_FILEMODE_WRITEAPPEND },
    { O_RDWR | O_TRUNC, MEDIA_FILEMODE_READWRITETRUNCATE },
    { O_RDWR | O_APPEND, MEDIA_FILEMODE_READWRITEAPPEND },
};

MediaFuseManager &MediaFuseManager::GetInstance()
{
    static MediaFuseManager instance;
    return instance;
}

void MediaFuseManager::Start()
{
    if (fuseDaemon_ != nullptr) {
        MEDIA_INFO_LOG("Fuse daemon already started");
        return;
    }

    std::string mountpoint;
    if (E_OK != MountFuse(mountpoint)) {
        MEDIA_ERR_LOG("MountFuse failed");
        return;
    }

    MEDIA_INFO_LOG("Mount fuse successfully, mountpoint = %{public}s", mountpoint.c_str());
    fuseDaemon_ = std::make_shared<MediaFuseDaemon>(mountpoint);

    if (E_OK != fuseDaemon_->StartFuse()) {
        MEDIA_INFO_LOG("Start fuse daemon failed");
        UMountFuse();
    }
}

void MediaFuseManager::Stop()
{
    MEDIA_INFO_LOG("Stop finished successfully");
}

int32_t MediaFuseManager::DoGetAttr(const char *path, struct stat *stbuf)
{
    if (path == nullptr || strlen(path) == 0) {
        MEDIA_ERR_LOG("Invalid path, %{private}s", path == nullptr ? "null" : path);
        return -ENOENT;
    }

    std::string target = ROOT_MEDIA_DIR + path;
    return lstat(target.c_str(), stbuf);
}

static int32_t GetFileIdFromPath(const string &filePath, string &fileId)
{
    NativeRdb::RdbPredicates rdbPredicate(PhotoColumn::PHOTOS_TABLE);
    rdbPredicate.And()->EqualTo(MediaColumn::MEDIA_FILE_PATH, filePath);

    vector<string> columns;
    columns.push_back(MediaColumn::MEDIA_ID);
    columns.push_back(MediaColumn::MEDIA_OWNER_APPID);
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    int32_t numRows = 0;
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to get rslt");
        return E_ERR;
    } else {
        resultSet->GetRowCount(numRows);
        if (numRows == 0) {
            MEDIA_ERR_LOG("Failed to get fileid: %{public}d", numRows);
            return E_ERR;
        } else {
            resultSet->GoToFirstRow();
            fileId = MediaLibraryRdbStore::GetString(resultSet, MediaColumn::MEDIA_ID);
            return E_SUCCESS;
        }
    }
}

static int32_t WrCheckPermission(const string &filePath, const string &mode, const uid_t &uid)
{
    vector<string> perms;
    if (mode.find("r") != string::npos) {
        perms.push_back(PERM_READ_IMAGEVIDEO);
    }
    if (mode.find("w") != string::npos) {
        perms.push_back(PERM_WRITE_IMAGEVIDEO);
    }
    return PermissionUtils::CheckPhotoCallerPermission(perms, uid)? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t DbCheckPermission(const string &filePath, const string &mode, const string &fileId, const string &appId)
{
    if (appId.empty() || fileId.empty()) {
        MEDIA_ERR_LOG("invalid input");
        return E_PERMISSION_DENIED;
    }
    NativeRdb::RdbPredicates rdbPredicate(TABLE_PERMISSION);
    rdbPredicate.And()->EqualTo("file_id", fileId);
    rdbPredicate.And()->EqualTo("appid", appId);
    vector<string> columns;
    columns.push_back(FIELD_PERMISSION_TYPE);
    columns.push_back("file_id");
    columns.push_back("appid");
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    int32_t permissionType = 0;
    int32_t numRows = 0;
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to get permission type");
        return E_PERMISSION_DENIED;
    } else {
        resultSet->GetRowCount(numRows);
        if (numRows == 0) {
            MEDIA_ERR_LOG("Failed to get fileid: %{public}d", numRows);
            return E_PERMISSION_DENIED;
        } else {
            resultSet->GoToFirstRow();
            permissionType = MediaLibraryRdbStore::GetInt(resultSet, FIELD_PERMISSION_TYPE);
            MEDIA_ERR_LOG("get permissionType %{public}d", permissionType);
        }
    }
    if (mode.find("r") != string::npos) {
        if (readPermSet.count(permissionType) == 0) {
            return E_PERMISSION_DENIED;
        }
    }
    if (mode.find("w") != string::npos) {
        if (writePermSet.count(permissionType) == 0) {
            return E_PERMISSION_DENIED;
        }
    }
    return E_SUCCESS;
}

static int32_t CheckPermission(const string &filePath, const string &mode, const string &fileId, const string &appId,
    const uid_t &uid)
{
    int err = WrCheckPermission(filePath, mode, uid);
    bool rslt;
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("wr check succ");
        return true;
    }
    err = DbCheckPermission(filePath, mode, fileId, appId);
    if (err == E_SUCCESS) {
        MEDIA_INFO_LOG("db check succ");
        rslt = true;
    } else {
        rslt = false;
    }
    if (mode.find("r") != string::npos) {
        PermissionUtils::CollectPermissionInfo(PERM_READ_IMAGEVIDEO, rslt,
            PermissionUsedTypeValue::PICKER_TYPE, uid);
    }
    if (mode.find("w") != string::npos) {
        PermissionUtils::CollectPermissionInfo(PERM_WRITE_IMAGEVIDEO, rslt,
            PermissionUsedTypeValue::PICKER_TYPE, uid);
    }
    return rslt;
}

static int32_t OpenFile(const string &filePath, const string &mode)
{
    string fileId;
    GetFileIdFromPath(filePath, fileId);
    fuse_context *ctx = fuse_get_context();
    uid_t uid = ctx->uid;
    string bundleName;
    MediaLibraryBundleManager::GetInstance()->GetBundleNameByUID(uid, bundleName);
    string appId = PermissionUtils::GetAppIdByBundleName(bundleName, uid);
    int32_t permGranted = CheckPermission(filePath, mode, fileId, appId, uid);
    if (permGranted == false) {
        return E_ERR;
    }
    return MediaPrivacyManager(filePath, mode, fileId, appId, bundleName, uid).Open();
}

int32_t MediaFuseManager::DoOpen(const char *path, int flags, int &fd)
{
    int realFlag = flags & (O_RDONLY | O_WRONLY | O_RDWR | O_TRUNC | O_APPEND);
    std::string target = FUSE_ROOT_MEDIA_DIR + path;
    fd = OpenFile(target.c_str(), MEDIA_OPEN_MODE_MAP.at(realFlag));
    if (fd < 0) {
        MEDIA_ERR_LOG("Open failed, path = %{private}s, errno = %{public}d", target.c_str(), errno);
        return E_ERR;
    }
    return 0;
}

int32_t MediaFuseManager::DoRelease(const char *path, const int &fd)
{
    string fileId;
    string filePath = FUSE_ROOT_MEDIA_DIR + path;
    GetFileIdFromPath(filePath, fileId);
    if (fd > 0) {
        close(fd);
        MediaLibraryObjectUtils::ScanFileAsync(filePath, fileId, MediaLibraryApi::API_10);
        return E_OK;
    } else {
        return E_ERR;
    }
}

int32_t MediaFuseManager::MountFuse(std::string &mountpoint)
{
    int devFd = -1;
    int32_t userId = 0;

    // get user id
    ErrCode ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("Get account fail, ret code %{public}d, result is not credible", ret);
        return E_FAIL;
    }

    // mount fuse
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    sptr<StorageManager::IStorageManager> proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    int32_t err = proxy_->MountMediaFuse(userId, devFd);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Mount failed for media fuse daemon, err = %{public}d", err);
        return err;
    }

    mountpoint = "/dev/fd/" + std::to_string(devFd);
    return E_OK;
}

int32_t MediaFuseManager::UMountFuse()
{
    int32_t userId = 0;

    // get user id
    ErrCode ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("Get account fail, ret code %{public}d, result is not credible", ret);
        return E_FAIL;
    }

    // umount fuse
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remote = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    sptr<StorageManager::IStorageManager> proxy_ = iface_cast<StorageManager::IStorageManager>(remote);
    int32_t err = proxy_->UMountMediaFuse(userId);
    if (err != E_OK) {
        MEDIA_ERR_LOG("UMount failed for media fuse daemon, err = %{public}d", err);
        return err;
    }
    return E_OK;
}
} // namespace Media
} // namespace OHOS

