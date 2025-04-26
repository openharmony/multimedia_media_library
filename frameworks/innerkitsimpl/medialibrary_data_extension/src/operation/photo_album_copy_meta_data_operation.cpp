/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "AlbumOperation"

#include "photo_album_copy_meta_data_operation.h"

#include "dfx_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_rdbstore.h"
#include "result_set_utils.h"

namespace OHOS::Media {

PhotoAlbumCopyMetaDataOperation &PhotoAlbumCopyMetaDataOperation::SetRdbStore(
    const std::shared_ptr<MediaLibraryRdbStore> &upgradeStore)
{
    this->mediaRdbStore_ = upgradeStore;
    return *this;
}

int64_t PhotoAlbumCopyMetaDataOperation::CopyAlbumMetaData(NativeRdb::ValuesBucket &values)
{
    CHECK_AND_RETURN_RET_LOG(this->mediaRdbStore_ != nullptr, -1, "rdbStore is null");
    AlbumInfo albumInfo;
    this->ReadAlbumValue(albumInfo, values);
    this->FindAlbumInfo(albumInfo);
    this->UpdateMetaData(albumInfo, values);
    return this->GetOrCreateAlbum(albumInfo.lPath, values);
}

void PhotoAlbumCopyMetaDataOperation::ReadAlbumValue(AlbumInfo &albumInfo, NativeRdb::ValuesBucket &values)
{
    std::string bundle_name = "";
    NativeRdb::ValueObject valueObject;
    if (values.GetObject(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, valueObject)) {
        valueObject.GetString(bundle_name);
        if (bundle_name == "com.huawei.ohos.screenshot") {
            bundle_name = "com.huawei.hmos.screenshot";
            values.Delete(PhotoAlbumColumns::ALBUM_BUNDLE_NAME);
            values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, bundle_name);
        }
        if (bundle_name == "com.huawei.ohos.screenrecorder") {
            bundle_name = "com.huawei.hmos.screenrecorder";
            values.Delete(PhotoAlbumColumns::ALBUM_BUNDLE_NAME);
            values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, bundle_name);
        }
    }
    int32_t album_type = -1;
    std::string album_name = "";
    if (values.GetObject(PhotoAlbumColumns::ALBUM_TYPE, valueObject)) {
        valueObject.GetInt(album_type);
    }
    if (values.GetObject(PhotoAlbumColumns::ALBUM_NAME, valueObject)) {
        valueObject.GetString(album_name);
    }
    values.PutInt(PhotoAlbumColumns::ALBUM_PRIORITY, 1);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_ADDED, MediaFileUtils::UTCTimeMilliSeconds());

    albumInfo.albumType = album_type;
    albumInfo.albumName = album_name;
    albumInfo.bundleName = bundle_name;
}

void PhotoAlbumCopyMetaDataOperation::FindAlbumInfo(AlbumInfo &albumInfo)
{
    std::string lPath = albumInfo.lPath;
    std::string bundle_name = albumInfo.bundleName;
    std::string album_name = albumInfo.albumName;
    if (albumInfo.albumType == OHOS::Media::PhotoAlbumType::SOURCE) {
        QueryAlbumPluginInfo(lPath, bundle_name, album_name);
    } else {
        lPath = "/Pictures/Users/" + album_name;
    }
    albumInfo.lPath = lPath;
    albumInfo.albumName = album_name;
    albumInfo.bundleName = bundle_name;
}

void PhotoAlbumCopyMetaDataOperation::UpdateMetaData(const AlbumInfo &albumInfo, NativeRdb::ValuesBucket &values)
{
    std::string lPath = albumInfo.lPath;
    std::string bundle_name = albumInfo.bundleName;
    std::string album_name = albumInfo.albumName;
    values.Delete(PhotoAlbumColumns::ALBUM_BUNDLE_NAME);
    values.PutString(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, bundle_name);
    values.Delete(PhotoAlbumColumns::ALBUM_NAME);
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, album_name);
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, lPath);
}

int64_t PhotoAlbumCopyMetaDataOperation::GetOrCreateAlbum(const std::string &lPath, NativeRdb::ValuesBucket &values)
{
    CHECK_AND_RETURN_RET_LOG(this->mediaRdbStore_ != nullptr, -1, "rdbStore is null");
    int32_t dirty = 0;
    int64_t albumId = this->GetLatestAlbumIdBylPath(lPath, dirty);
    bool isExist = (albumId > 0);
    if (isExist) {
        if (dirty == static_cast<int32_t>(DirtyTypes::TYPE_DELETED)) {
            MEDIA_INFO_LOG("Reuse deleted photo album: album_id = %{public}lld, lPath = %{public}s",
                static_cast<long long>(albumId), DfxUtils::GetSafeAlbumName(lPath).c_str());
            int32_t renewRet = MediaLibraryAlbumOperations::RenewDeletedPhotoAlbum(albumId, values, nullptr);
            CHECK_AND_PRINT_LOG(renewRet == E_OK, "Failed to update deleted album: %{public}lld",
                static_cast<long long>(albumId));
        }
        return albumId;
    }

    int64_t newAlbumId = -1;
    int32_t ret = this->mediaRdbStore_->Insert(newAlbumId, PhotoAlbumColumns::TABLE, values);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Insert copyed album failed, ret = %{public}d", ret);
    MEDIA_INFO_LOG("Create new album: album_id = %{public}lld, lPath = %{public}s",
        static_cast<long long>(newAlbumId), DfxUtils::GetSafeAlbumName(lPath).c_str());
    return newAlbumId;
}

int64_t PhotoAlbumCopyMetaDataOperation::GetLatestAlbumIdBylPath(const std::string &lPath, int32_t &dirty)
{
    bool cond = (lPath.empty() || this->mediaRdbStore_ == nullptr);
    CHECK_AND_RETURN_RET_LOG(!cond, -1, "rdbStore or lpath is null, lPath: %{public}s",
        DfxUtils::GetSafeAlbumName(lPath).c_str());

    const std::vector<NativeRdb::ValueObject> params = {lPath};
    auto resultSet = this->mediaRdbStore_->QuerySql(this->SQL_PHOTO_ALBUM_SELECT_MAX_ALBUM_ID_BY_LPATH, params);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, -1, "resultSet is nullptr");

    CHECK_AND_RETURN_RET_INFO_LOG(resultSet->GoToFirstRow() == NativeRdb::E_OK, -1,
        "No exist album found by lpath");
    int64_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    CHECK_AND_RETURN_RET_LOG(albumId > 0, -1, "invalid album id");

    dirty = GetInt32Val(PhotoAlbumColumns::ALBUM_DIRTY, resultSet);
    return albumId;
}

int32_t PhotoAlbumCopyMetaDataOperation::QueryAlbumPluginInfo(std::string &lPath, std::string &bundle_name,
    std::string &album_name)
{
    CHECK_AND_RETURN_RET_LOG(this->mediaRdbStore_ != nullptr, E_INVALID_ARGUMENTS, "rdbStore is null");

    std::string queryExpiredAlbumInfo = "";
    std::vector<NativeRdb::ValueObject> bindArgs = {album_name, album_name};
    if (bundle_name.empty()) {
        queryExpiredAlbumInfo = this->SQL_ALBUM_PLUGIN_SELECT_BY_NAME;
    } else {
        queryExpiredAlbumInfo = this->SQL_ALBUM_PLUGIN_SELECT_BY_BUNDLE_AND_NAME;
        bindArgs.emplace_back(bundle_name);
    }
    auto resultSet = this->mediaRdbStore_->QuerySql(queryExpiredAlbumInfo, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INVALID_ARGUMENTS, "resultSet is nullptr");

    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        lPath = "/Pictures/" + album_name;
        return E_OK;
    }
    lPath = GetStringVal(PhotoAlbumColumns::ALBUM_LPATH, resultSet);
    if (lPath.empty()) {
        lPath = "/Pictures/" + album_name;
    }
    bundle_name = GetStringVal(PhotoAlbumColumns::ALBUM_BUNDLE_NAME, resultSet);
    album_name = GetStringVal(PhotoAlbumColumns::ALBUM_NAME, resultSet);
    return E_OK;
}
} // namespace OHOS::Media