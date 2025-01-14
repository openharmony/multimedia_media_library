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
#define MLOG_TAG "PhotoOtherAlbumTransOperation"

#include "photo_other_album_trans_operation.h"

#include <cerrno>
#include <functional>
#include <iomanip>
#include <sstream>
#include <string>

#include "medialibrary_type_const.h"
#include "medialibrary_formmap_operations.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdbstore.h"
#include "metadata.h"
#include "media_file_utils.h"
#include "medialibrary_album_fusion_utils.h"
#include "parameters.h"
#include "photo_file_operation.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"

namespace OHOS::Media {
using namespace std;
using namespace NativeRdb;
std::shared_ptr<PhotoOtherAlbumTransOperation> PhotoOtherAlbumTransOperation::instance_ = nullptr;
std::mutex PhotoOtherAlbumTransOperation::objMutex_;

PhotoOtherAlbumTransOperation &PhotoOtherAlbumTransOperation::GetInstance()
{
    std::lock_guard<std::mutex> lock(PhotoOtherAlbumTransOperation::objMutex_);
    if (PhotoOtherAlbumTransOperation::instance_ == nullptr) {
        PhotoOtherAlbumTransOperation::instance_ = std::make_shared<PhotoOtherAlbumTransOperation>();
    }
    return *PhotoOtherAlbumTransOperation::instance_;
}

PhotoOtherAlbumTransOperation &PhotoOtherAlbumTransOperation::Start()
{
    this->isContinue_.store(true);
    return *this;
}

void PhotoOtherAlbumTransOperation::Stop()
{
    this->isContinue_.store(false);
}

void PhotoOtherAlbumTransOperation::BuildOtherAlbumInsertValues(
    const std::shared_ptr<MediaLibraryRdbStore> upgradeStore, const string &albumName, const string &lpath,
    const string &bundleName, std::vector<std::pair<int64_t, std::string>> &transAlbum)
{
    MEDIA_INFO_LOG("Begin build insert values meta data on other album trans");
    if (upgradeStore == nullptr) {
        MEDIA_ERR_LOG("fail to get rdbstore");
        return;
    }
    bool isAlbumExist = false;
    for (const auto &transPair : transAlbum) {
        if (transPair.second == albumName) {
            isAlbumExist = true;
            break;
        }
    }
    if (isAlbumExist) {
        MEDIA_INFO_LOG("Other album need trans is already exist!");
        return;
    }
    MEDIA_INFO_LOG("Start build album on other album trans, name is: %{public}s", albumName.c_str());
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::SOURCE);
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumSubType::SOURCE_GENERIC);
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, bundleName);
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, 1);
    values.PutInt(PhotoAlbumColumns::ALBUM_IS_LOCAL, 1);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, MediaFileUtils::UTCTimeMilliSeconds());
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, lpath);
    values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, 1);
    int64_t newAlbumId = 0;
    int32_t ret = upgradeStore->Insert(newAlbumId, PhotoAlbumColumns::TABLE, values);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Insert db fail, ret = %{public}d", ret);
        return;
    }
    transAlbum.emplace_back(make_pair(newAlbumId, albumName));
}

bool PhotoOtherAlbumTransOperation::CheckIfNeedTransOtherAlbumData(
    const std::shared_ptr<MediaLibraryRdbStore> upgradeStore, int64_t otherAlbumId,
    std::vector<std::pair<int64_t, std::string>> &transAlbum)
{
    bool isNeedTrans = false;
    const std::string QUERY_OTHER_ALBUM_CAMERA_TRANS =
        "SELECT * FROM Photos WHERE owner_album_id = " + std::to_string(otherAlbumId) +
        " AND (title LIKE 'IMG_%' OR title LIKE 'VID_%')";
    shared_ptr<NativeRdb::ResultSet> resultSetCamera = upgradeStore->QuerySql(QUERY_OTHER_ALBUM_CAMERA_TRANS);
    int rowCount = 0;
    resultSetCamera->GetRowCount(rowCount);
    if (rowCount > 0) {
        MEDIA_INFO_LOG("Need to trans other camera album data, count is: %{public}d", rowCount);
        BuildOtherAlbumInsertValues(upgradeStore, "相机", "/DCIM/Camera", "com.huawei.hmos.camera", transAlbum);
        isNeedTrans = true;
    }

    const std::string QUERY_OTHER_ALBUM_SCREENSHOT_TRANS =
        "SELECT * FROM Photos WHERE owner_album_id = " + std::to_string(otherAlbumId) +
        " AND title LIKE 'screenshot_%'";
    shared_ptr<NativeRdb::ResultSet> resultSetScreenshot = upgradeStore->QuerySql(QUERY_OTHER_ALBUM_SCREENSHOT_TRANS);
    resultSetScreenshot->GetRowCount(rowCount);
    if (rowCount > 0) {
        MEDIA_INFO_LOG("Need to trans other screenshot album data, count is: %{public}d", rowCount);
        BuildOtherAlbumInsertValues(upgradeStore, "截图", "/Pictures/Screenshots",
            "com.huawei.hmos.screenshot", transAlbum);
        isNeedTrans = true;
    }

    const std::string QUERY_OTHER_ALBUM_RECORD_TRANS =
        "SELECT * FROM Photos WHERE owner_album_id = " + std::to_string(otherAlbumId) + " AND title LIKE 'SVID_%'";
    shared_ptr<NativeRdb::ResultSet> resultSetRecord = upgradeStore->QuerySql(QUERY_OTHER_ALBUM_RECORD_TRANS);
    resultSetRecord->GetRowCount(rowCount);
    if (rowCount > 0) {
        MEDIA_INFO_LOG("Need to trans other screenrecord album data, count is: %{public}d", rowCount);
        BuildOtherAlbumInsertValues(upgradeStore, "屏幕录制", "/Pictures/Screenrecords",
            "com.huawei.hmos.screenrecorder", transAlbum);
        isNeedTrans = true;
    }

    const std::string QUERY_OTHER_ALBUM_WECHAT_TRANS =
        "SELECT * FROM Photos WHERE owner_album_id = " + std::to_string(otherAlbumId) +
        " AND (title LIKE 'mmexport%' OR title LIKE 'wx_camera_%')";
    shared_ptr<NativeRdb::ResultSet> resultSetWechat = upgradeStore->QuerySql(QUERY_OTHER_ALBUM_WECHAT_TRANS);
    resultSetWechat->GetRowCount(rowCount);
    if (rowCount > 0) {
        MEDIA_INFO_LOG("Need to trans other WeChat album data, count is: %{public}d", rowCount);
        BuildOtherAlbumInsertValues(upgradeStore, "微信", "/Pictures/WeiXin", "", transAlbum);
        isNeedTrans = true;
    }
    return isNeedTrans;
}

int32_t PhotoOtherAlbumTransOperation::DealWithOtherAlbumTrans(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
    std::pair<int64_t, std::string> transInfo, int64_t otherAlbumId)
{
    std::string sourcePathName = "";
    std::string sqlWherePrefix = "";
    std::string transAlbumName = transInfo.second;
    int64_t transAlbumId = transInfo.first;
    if (transAlbumName == SCREENSHOT_ALBUM_NAME) {
        sourcePathName = "Pictures/Screenshots";
        sqlWherePrefix = "title LIKE 'screenshot_%'";
    } else if (transAlbumName == SCREENRECORD_ALBUM_NAME) {
        sourcePathName = "Pictures/Screenshots";
        sqlWherePrefix = "title LIKE 'SVID_%'";
    } else if (transAlbumName == WECHAT_ALBUM_NAME) {
        sourcePathName = "Pictures/WeiXin";
        sqlWherePrefix = "title LIKE 'mmexport%' OR title LIKE 'wx_camera_%'";
    } else if (transAlbumName == ALBUM_NAME_CAMERA) {
        sourcePathName = "DCIM/camera";
        sqlWherePrefix = "(title LIKE 'IMG_%' OR title LIKE 'VID_%')";
    } else {
        MEDIA_ERR_LOG("Invalid trans album name %{public}s", transInfo.second.c_str());
        return E_DB_FAIL;
    }

    const std::string UPDATE_OTHER_ALBUM_TRANS =
        "UPDATE Photos SET owner_album_id = " + std::to_string(transAlbumId) +
        ", source_path = REPLACE(source_path, '/storage/emulated/0/Pictures/其它/', '/storage/emulated/0/" +
        sourcePathName + "/') WHERE owner_album_id = " + std::to_string(otherAlbumId) + " AND " + sqlWherePrefix;
    int32_t err = upgradeStore->ExecuteSql(UPDATE_OTHER_ALBUM_TRANS);
    MEDIA_INFO_LOG("Trans other sql is: %{public}s", UPDATE_OTHER_ALBUM_TRANS.c_str());
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Fatal error! Failed to exec: %{public}s", UPDATE_OTHER_ALBUM_TRANS.c_str());
        return err;
    }
    MEDIA_INFO_LOG("Trans other album success");
    return E_OK;
}

bool PhotoOtherAlbumTransOperation::IsOtherAlbumEmpty(
    const int64_t &otherAlbumId, const std::shared_ptr<MediaLibraryRdbStore> upgradeStore)
{
    const std::string QUERY_OTHER_ALBUM_COUNT =
        "SELECT * FROM PhotoAlbum WHERE album_id = " + std::to_string(otherAlbumId);
    shared_ptr<NativeRdb::ResultSet> resultSet = upgradeStore->QuerySql(QUERY_OTHER_ALBUM_COUNT);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Query other album count fail");
        return true;
    }
    int32_t albumDataCount = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
    if (albumDataCount <= 0) {
        MEDIA_INFO_LOG("Other album empty");
        return true;
    }
    MEDIA_INFO_LOG("Other album not empty");
    return false;
}

void PhotoOtherAlbumTransOperation::GetOtherAlbumIdInfo(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
    int64_t &otherAlbumId, std::vector<std::pair<int64_t, std::string>> &transAlbum)
{
    const std::string QUERY_TRANS_ALBUM_INFO =
        "SELECT * FROM PhotoAlbum WHERE lpath IN "
        "('/Pictures/Screenshots', '/Pictures/Screenrecords', '/DCIM/Camera', '/Pictures/WeiXin', '/Pictures/其它')";
    shared_ptr<NativeRdb::ResultSet> resultSet = upgradeStore->QuerySql(QUERY_TRANS_ALBUM_INFO);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query not matched data fails");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int64_t albumId = GetInt64Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
        std::string albumName = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
        if (albumName == OTHER_ALBUM_NAME) {
            otherAlbumId = albumId;
        } else {
            transAlbum.emplace_back(make_pair(albumId, albumName));
        }
        MEDIA_INFO_LOG("Trans album name %{public}s, id is %{public}s", albumName.c_str(), to_string(albumId).c_str());
    }
}

int32_t PhotoOtherAlbumTransOperation::TransOtherAlbumData(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
    bool &isNeedUpdate)
{
    MEDIA_INFO_LOG("Start trans other Album to origin album");
    if (upgradeStore == nullptr) {
        MEDIA_ERR_LOG("fail to get rdbstore");
        return E_DB_FAIL;
    }

    std::vector<std::pair<int64_t, std::string>> transAlbum;
    int64_t otherAlbumId = -1;
    GetOtherAlbumIdInfo(upgradeStore, otherAlbumId, transAlbum);
    if (otherAlbumId == -1) {
        MEDIA_INFO_LOG("No other album data need trans");
        return E_DB_FAIL;
    }
    if (IsOtherAlbumEmpty(otherAlbumId, upgradeStore)) {
        return E_DB_FAIL;
    }

    if (!CheckIfNeedTransOtherAlbumData(upgradeStore, otherAlbumId, transAlbum)) {
        MEDIA_INFO_LOG("No other album data need to trans");
        return E_DB_FAIL;
    }
    isNeedUpdate = true;
    int64_t beginTime = MediaFileUtils::UTCTimeMilliSeconds();
    for (auto transInfo: transAlbum) {
        if (!this->isContinue_.load()) {
            MEDIA_INFO_LOG("Media_Operation: Trans other album is not allowed.");
            break;
        }
        DealWithOtherAlbumTrans(upgradeStore, transInfo, otherAlbumId);
    }
    MEDIA_INFO_LOG("Trans album cost %{public}ld",
        (long)(MediaFileUtils::UTCTimeMilliSeconds() - beginTime));
    return E_OK;
}
} // namespace OHOS::Media