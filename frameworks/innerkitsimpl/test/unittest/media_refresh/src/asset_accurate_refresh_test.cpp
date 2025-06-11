/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "AssetAccurateRefreshTest"
#include "asset_accurate_refresh_test.h"

#include <chrono>
#include <thread>

#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_type_const.h"

#include "accurate_debug_log.h"
#define protected public
#define private public
#include "asset_accurate_refresh.h"
#undef protected
#undef private

#include "accurate_refresh_test_util.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace AccurateRefresh;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;

static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

namespace {
// ����
// ��ͨ�ʲ����ղء���Ƶ�����ء�ͼƬ��
    
const int32_t ASSET_FILE_ID = 0; // ���ݿ��������ֵ
const string ASSET_URI = "uri"; // ��file_id����
const string ASSET_DATE_DAY = "20250525";
const int64_t ASSET_DATE_TRASH = 123451234567;
const int32_t ASSET_MEDIA_TYPE_VIDEO = static_cast<int32_t>(MEDIA_TYPE_VIDEO);
const int32_t ASSET_MEDIA_TYPE_IMAGE = static_cast<int32_t>(MEDIA_TYPE_IMAGE);
const int32_t ASSET_STRONG_ASSOCIATION_NORMAL = static_cast<int32_t>(StrongAssociationType::NORMAL);
const int32_t ASSET_STRONG_ASSOCIATION_CLOUD = static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT);
const int32_t ASSET_THUMBNAIL_VISIBLE = 1;
const int64_t ASSET_DATE_ADDED = 123456;
const int64_t ASSET_DATE_TAKEN = 123456;
const int32_t ASSET_SUBTYPE_DEFAULT = static_cast<int32_t>(PhotoSubType::DEFAULT);
const int32_t ASSET_SYNC_STATUS_VISIBLE = static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE);
const int32_t ASSET_CLEAN_FLAG_NO = static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN);
const int32_t ASSET_BURST_COVER_LEVEL = static_cast<int32_t>(BurstCoverLevelType::COVER);
const string ASSET_DISPLAY_NAME = "asset_display_name";
const string ASSET_PATH = "asset_path";
const string OWNER_ALBUM_URI_ = "file://media/PhotoAlbum/";
const int64_t ASSET_HIDDEN_TIME = 54321;

const int32_t FAVORITE_VIDEO_ASSET_ALBUM_ID = 100;
const int32_t FAVORITE_VIDEO_ASSET_FILE_ID = 10000;

const int32_t VIDEO_ASSET_ALBUM_ID = 200;
const int32_t VIDEO_ASSET_FILE_ID = 2000;

const int32_t FAVORITE_IMAGE_ASSET_ALBUM_ID = 300;
const int32_t FAVORITE_IMAGE_ASSET_FILE_ID = 30000;

const int32_t IMAGE_ASSET_ALBUM_ID = 400;
const int32_t IMAGE_ASSET_FILE_ID = 40000;

const int32_t FAVORITE_VIDEO_HIDDEN_ASSET_ALBUM_ID = 500;
const int32_t FAVORITE_VIDEO_HIDDEN_ASSET_FILE_ID = 50000;

const int32_t VIDEO_HIDDEN_ASSET_ALBUM_ID = 600;
const int32_t VIDEO_HIDDEN_ASSET_FILE_ID = 60000;

const int32_t FAVORITE_IMAGE_HIDDEN_ASSET_ALBUM_ID = 700;
const int32_t FAVORITE_IMAGE_HIDDEN_ASSET_FILE_ID = 70000;

const int32_t IMAGE_HIDDEN_ASSET_ALBUM_ID = 800;
const int32_t IMAGE_HIDDEN_ASSET_FILE_ID = 80000;

const int32_t IMAGE_CLOUD_ASSET_ALBUM_ID = 900;
const int32_t IMAGE_CLOUD_ASSET_FILE_ID = 90000;

const int32_t IMAGE_TRASH_ASSET_ALBUM_ID = 1000;
const int32_t IMAGE_TRASH_ASSET_FILE_ID = 100000;

const PhotoAssetChangeInfo NORMAL_ASSET = { ASSET_FILE_ID, ASSET_URI, ASSET_DATE_DAY,
    "uri", // owner album uri
    false, // isFavorite
    ASSET_MEDIA_TYPE_IMAGE, // default image
    false, // isHidden
    0,  // dateTrash
    ASSET_STRONG_ASSOCIATION_NORMAL,
    ASSET_THUMBNAIL_VISIBLE, ASSET_DATE_ADDED, ASSET_DATE_TAKEN, ASSET_SUBTYPE_DEFAULT, ASSET_SYNC_STATUS_VISIBLE,
    ASSET_CLEAN_FLAG_NO,
    0, // timePending
    false, // isTemp
    ASSET_BURST_COVER_LEVEL,
    0, // owner album id
    0, // hidden time
    ASSET_DISPLAY_NAME,
    ASSET_PATH
};

void SetTables()
{
    // ����Photos/PhotoAlbum��
    vector<string> createTableSqlList = {
        CREATE_PHOTO_ALBUM_TABLE,
        CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_INFO_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
    MEDIA_INFO_LOG("SetTables");
}

void PrepareAlbumData()
{
    vector<ValuesBucket> values;
    values.push_back(GetFavoriteInsertAlbum());
    values.push_back(GetHiddenInsertAlbum());
    values.push_back(GetTrashInsertAlbum());
    values.push_back(GetVideoInsertAlbum());
    values.push_back(GetImageInsertAlbum());
    values.push_back(GetCloudEnhancementInsertAlbum());

    values.push_back(GetUserInsertAlbum(FAVORITE_VIDEO_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(VIDEO_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(FAVORITE_IMAGE_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(IMAGE_ASSET_ALBUM_ID));

    values.push_back(GetUserInsertAlbum(FAVORITE_VIDEO_HIDDEN_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(VIDEO_HIDDEN_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(FAVORITE_IMAGE_HIDDEN_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(IMAGE_HIDDEN_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(IMAGE_CLOUD_ASSET_ALBUM_ID));
    values.push_back(GetUserInsertAlbum(IMAGE_TRASH_ASSET_ALBUM_ID));

    int64_t insertNums = 0;
    auto ret = g_rdbStore->BatchInsert(insertNums, PhotoAlbumColumns::TABLE, values);
    ACCURATE_DEBUG("ret: %{public}d, insert values: %{public}" PRId64, ret, insertNums);
}

void CleanTestTables()
{
    vector<string> dropTableList = {
        PhotoAlbumColumns::TABLE,
        PhotoColumn::PHOTOS_TABLE,
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_INFO_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}

// �ղء���Ƶ��������
PhotoAssetChangeInfo GetFavoriteVideoAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.fileId_ = FAVORITE_VIDEO_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = FAVORITE_VIDEO_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(FAVORITE_VIDEO_ASSET_ALBUM_ID);
    assetChangeInfo.mediaType_ = ASSET_MEDIA_TYPE_VIDEO;

    return assetChangeInfo;
}

// ���ղء���Ƶ��������
PhotoAssetChangeInfo GetVideoAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = VIDEO_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = VIDEO_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(VIDEO_ASSET_ALBUM_ID);
    assetChangeInfo.mediaType_ = ASSET_MEDIA_TYPE_VIDEO;
    return assetChangeInfo;
}

// �ղء�ͼƬ(MEDIA_TYPE_IMAGE)��������
PhotoAssetChangeInfo GetFavoriteImageAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.fileId_ = FAVORITE_IMAGE_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = FAVORITE_IMAGE_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(FAVORITE_IMAGE_ASSET_ALBUM_ID);
    return assetChangeInfo;
}

// ���ղء�ͼƬ��������
PhotoAssetChangeInfo GetImageAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = IMAGE_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = IMAGE_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(IMAGE_ASSET_ALBUM_ID);
    return assetChangeInfo;
}

// �ղء���Ƶ������
PhotoAssetChangeInfo GetFavoriteVideoHiddenAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.fileId_ = FAVORITE_VIDEO_HIDDEN_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = FAVORITE_VIDEO_HIDDEN_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(FAVORITE_VIDEO_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.mediaType_ = ASSET_MEDIA_TYPE_VIDEO;
    assetChangeInfo.isHidden_ = true;
    assetChangeInfo.hiddenTime_ = ASSET_HIDDEN_TIME;
    return assetChangeInfo;
}

// ���ղء���Ƶ������
PhotoAssetChangeInfo GetVideoHiddenAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = VIDEO_HIDDEN_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = VIDEO_HIDDEN_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(VIDEO_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.mediaType_ = ASSET_MEDIA_TYPE_VIDEO;
    assetChangeInfo.isHidden_ = true;
    assetChangeInfo.hiddenTime_ = ASSET_HIDDEN_TIME;
    return assetChangeInfo;
}
// �ղء�ͼƬ������
PhotoAssetChangeInfo GetFavoriteImageHiddenAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.isFavorite_ = true;
    assetChangeInfo.fileId_ = FAVORITE_IMAGE_HIDDEN_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = FAVORITE_IMAGE_HIDDEN_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(FAVORITE_IMAGE_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.isHidden_ = true;
    assetChangeInfo.hiddenTime_ = ASSET_HIDDEN_TIME;
    return assetChangeInfo;
}

// ���ղء�ͼƬ������
PhotoAssetChangeInfo GetImageHiddenAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = IMAGE_HIDDEN_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = IMAGE_HIDDEN_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(IMAGE_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.isHidden_ = true;
    assetChangeInfo.hiddenTime_ = ASSET_HIDDEN_TIME;
    return assetChangeInfo;
}

// ��ͬ���ʲ�
PhotoAssetChangeInfo GetCloudAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = IMAGE_CLOUD_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = IMAGE_CLOUD_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(IMAGE_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.strongAssociation_ = ASSET_STRONG_ASSOCIATION_CLOUD;
    return assetChangeInfo;
}

// ����վ�ʲ�
PhotoAssetChangeInfo GetTrashAsset()
{
    PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.fileId_ = IMAGE_TRASH_ASSET_FILE_ID;
    assetChangeInfo.ownerAlbumId_ = IMAGE_TRASH_ASSET_ALBUM_ID;
    assetChangeInfo.ownerAlbumUri_ = OWNER_ALBUM_URI_ + to_string(IMAGE_HIDDEN_ASSET_ALBUM_ID);
    assetChangeInfo.dateTrashedMs_ = ASSET_DATE_TRASH;
    return assetChangeInfo;
}

ValuesBucket GetAssetInsertValue(PhotoAssetChangeInfo assetInfo)
{
    ValuesBucket value;
    value.PutInt(PhotoColumn::MEDIA_ID, assetInfo.fileId_);
    value.PutString(PhotoColumn::PHOTO_DATE_DAY, assetInfo.dateDay_);
    value.PutInt(PhotoColumn::MEDIA_IS_FAV, static_cast<int32_t>(assetInfo.isFavorite_));
    value.PutInt(PhotoColumn::MEDIA_TYPE, assetInfo.mediaType_);
    value.PutInt(PhotoColumn::MEDIA_HIDDEN, assetInfo.isHidden_);
    value.PutLong(PhotoColumn::MEDIA_DATE_TRASHED, assetInfo.dateTrashedMs_);
    value.PutInt(PhotoColumn::PHOTO_STRONG_ASSOCIATION, assetInfo.strongAssociation_);
    value.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, assetInfo.thumbnailVisible_);
    value.PutLong(PhotoColumn::MEDIA_DATE_ADDED, assetInfo.dateAddedMs_);
    value.PutLong(PhotoColumn::MEDIA_DATE_TAKEN, assetInfo.dateTakenMs_);
    value.PutInt(PhotoColumn::PHOTO_SUBTYPE, assetInfo.subType_);
    value.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, assetInfo.syncStatus_);
    value.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, assetInfo.cleanFlag_);
    value.PutInt(PhotoColumn::MEDIA_TIME_PENDING, assetInfo.timePending_);
    value.PutInt(PhotoColumn::PHOTO_IS_TEMP, assetInfo.isTemp_);
    value.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, assetInfo.burstCoverLevel_);
    value.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, assetInfo.ownerAlbumId_);
    value.PutLong(PhotoColumn::PHOTO_HIDDEN_TIME, assetInfo.hiddenTime_);
    value.PutString(PhotoColumn::MEDIA_NAME, assetInfo.displayName_);
    value.PutString(PhotoColumn::MEDIA_FILE_PATH, assetInfo.path_);
    return value;
}

PhotoAssetChangeInfo GetAssetInfo(int32_t fileId = 0)
{
    RdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileId));

    auto resultSet = g_rdbStore->QueryByStep(queryPredicates, PhotoAssetChangeInfo::GetPhotoAssetClolumns());
    EXPECT_TRUE(resultSet != nullptr);
    auto assetInfos = PhotoAssetChangeInfo::GetInfoFromResult(resultSet, PhotoAssetChangeInfo::GetPhotoAssetClolumns());
    if (assetInfos.size() == 1) {
        ACCURATE_DEBUG("assetInfo: %{public}s", assetInfos[0].ToString().c_str());
        return assetInfos[0];
    }
    ACCURATE_DEBUG("asset info wrong: %{public}zu.", assetInfos.size());
    return PhotoAssetChangeInfo();
}

bool CheckAssetEqual(const PhotoAssetChangeInfo &changeInfo1, const PhotoAssetChangeInfo &changeInfo2)
{
    ACCURATE_DEBUG("%{public}s", changeInfo1.ToString().c_str());
    ACCURATE_DEBUG("%{public}s", changeInfo2.ToString().c_str());
    return changeInfo1.fileId_ == changeInfo2.fileId_;
}

bool CheckAssetChangeData(const PhotoAssetChangeData &changeData1, const PhotoAssetChangeData &changeData2)
{
    if (changeData1.isContentChanged_ != changeData2.isContentChanged_) {
        MEDIA_ERR_LOG("isContentChanged_(%{public}d/%{public}d) wrong", changeData1.isContentChanged_,
            changeData2.isContentChanged_);
        return false;
    }

    if (changeData1.isDelete_ != changeData2.isDelete_) {
        MEDIA_ERR_LOG("isDelete_(%{public}d/%{public}d) wrong", changeData1.isDelete_, changeData2.isDelete_);
        return false;
    }

    if (changeData1.operation_ != changeData2.operation_) {
        MEDIA_ERR_LOG("operation_(%{public}d/%{public}d) wrong", changeData1.operation_, changeData2.operation_);
        return false;
    }

    if (changeData1.infoBeforeChange_.ownerAlbumId_ != changeData2.infoBeforeChange_.ownerAlbumId_) {
        MEDIA_ERR_LOG("ownerAlbumId_(%{public}d/%{public}d) wrong", changeData1.infoBeforeChange_.ownerAlbumId_,
            changeData2.infoBeforeChange_.ownerAlbumId_);
        return false;
    }

    if (changeData1.infoAfterChange_.ownerAlbumId_ != changeData2.infoAfterChange_.ownerAlbumId_) {
        MEDIA_ERR_LOG("ownerAlbumId_(%{public}d/%{public}d) wrong", changeData1.infoAfterChange_.ownerAlbumId_,
            changeData2.infoAfterChange_.ownerAlbumId_);
        return false;
    }
    return true;
}

bool CheckInsertAlbumInfo(const AlbumChangeInfo &refreshAlbumInfo, AlbumChangeInfo initAlbumInfo,
    const PhotoAssetChangeInfo &queryAssetInfo, map<int32_t, AlbumChangeData> &albumChangeDatas)
{
    // ������Ϣ
    auto expectedAlbumInfo = initAlbumInfo;
    if (!queryAssetInfo.isHidden_) {
        // ��ͨ�ʲ���������
        expectedAlbumInfo.count_++;
        if (queryAssetInfo.mediaType_ == static_cast<int32_t>(MEDIA_TYPE_VIDEO)) {
            expectedAlbumInfo.videoCount_++;
        } else if (queryAssetInfo.mediaType_ == static_cast<int32_t>(MEDIA_TYPE_IMAGE)) {
            expectedAlbumInfo.imageCount_++;
        }
        // �������
        // ��Ƶ��ͼƬΪdate_added������ΪdateTaken
        bool isDateAdded = initAlbumInfo.albumId_ == IMAGE_ALBUM_ID || initAlbumInfo.albumId_ == VIDEO_ALBUM_ID;
        auto queryAssetCoverDateTime = isDateAdded ? queryAssetInfo.dateAddedMs_ : queryAssetInfo.dateTakenMs_;
        if (queryAssetCoverDateTime > initAlbumInfo.coverDateTime_) {
            expectedAlbumInfo.coverDateTime_ = queryAssetCoverDateTime;
            expectedAlbumInfo.coverUri_ = queryAssetInfo.uri_;
            if (!CheckAssetEqual(refreshAlbumInfo.coverInfo_, queryAssetInfo)) {
                MEDIA_ERR_LOG("cover info wrong");
                return false;
            }
        } else {
            if (!CheckAssetEqual(refreshAlbumInfo.coverInfo_, initAlbumInfo.coverInfo_)) {
                MEDIA_ERR_LOG("cover info wrong");
                return false;
            }
        }
    } else {
        // �����ʲ���������
        expectedAlbumInfo.hiddenCount_++;
        // �����ʲ��������
        if (queryAssetInfo.hiddenTime_ > initAlbumInfo.hiddenCoverDateTime_) {
            expectedAlbumInfo.hiddenCoverDateTime_ = queryAssetInfo.hiddenTime_;
            expectedAlbumInfo.hiddenCoverUri_ = queryAssetInfo.uri_;
            if (!CheckAssetEqual(refreshAlbumInfo.hiddenCoverInfo_, queryAssetInfo)) {
                MEDIA_ERR_LOG("hidden cover info wrong");
                return false;
            }
        } else {
            if (!CheckAssetEqual(refreshAlbumInfo.hiddenCoverInfo_, initAlbumInfo.hiddenCoverInfo_)) {
                MEDIA_ERR_LOG("hidden cover info wrong");
                return false;
            }
        }
    }
    if (!IsEqualAlbumInfo(refreshAlbumInfo, expectedAlbumInfo)) {
        MEDIA_ERR_LOG("album info wrong");
        return false;
    }
    AlbumChangeData albumChangeData;
    albumChangeData.infoBeforeChange_ = initAlbumInfo;
    albumChangeData.infoAfterChange_ = expectedAlbumInfo;
    albumChangeData.isDelete_ = false;
    albumChangeDatas.emplace(initAlbumInfo.albumId_, albumChangeData);
    // ���ݿ���Ϣ
    auto queryAlbumInfo = GetAlbumInfo(refreshAlbumInfo.albumId_, g_rdbStore);
    if (!IsEqualAlbumInfo(refreshAlbumInfo, queryAlbumInfo)) {
        MEDIA_ERR_LOG("database album info wrong");
        return false;
    }
    return true;
}

bool CheckInsertHiddenAlbum(const AlbumChangeInfo &refreshHiddenAlbumInfo, AlbumChangeInfo initHiddenAlbumInfo,
    const PhotoAssetChangeInfo &queryAssetInfo, map<int32_t, AlbumChangeData> &albumChangeDatas)
{
    AlbumChangeInfo expectedAlbumInfo = initHiddenAlbumInfo;
    if (queryAssetInfo.isHidden_) {
        // ����������
        expectedAlbumInfo.count_++;
        expectedAlbumInfo.hiddenCount_++;
        if (queryAssetInfo.mediaType_ == static_cast<int32_t>(MEDIA_TYPE_VIDEO)) {
            expectedAlbumInfo.videoCount_++;
        } else {
            expectedAlbumInfo.imageCount_++;
        }
        if (refreshHiddenAlbumInfo.hiddenCoverDateTime_ < queryAssetInfo.hiddenTime_) {
            expectedAlbumInfo.hiddenCoverDateTime_ = queryAssetInfo.hiddenTime_;
            expectedAlbumInfo.hiddenCoverUri_ = queryAssetInfo.uri_;
            if (!CheckAssetEqual(refreshHiddenAlbumInfo.coverInfo_, queryAssetInfo)) {
                MEDIA_ERR_LOG("hidden cover info not refresh");
                return false;
            }
        } else {
            if (!CheckAssetEqual(refreshHiddenAlbumInfo.coverInfo_, initHiddenAlbumInfo.coverInfo_)) {
                MEDIA_ERR_LOG("hidden cover info wrong");
                return false;
            }
        }
    } else {
        MEDIA_ERR_LOG("not hidden asset.");
        return false;
    }
    if (!IsEqualAlbumInfo(refreshHiddenAlbumInfo, expectedAlbumInfo)) {
        return false;
    }
    AlbumChangeData albumChangeData;
    albumChangeData.infoBeforeChange_ = initHiddenAlbumInfo;
    albumChangeData.infoAfterChange_ = expectedAlbumInfo;
    albumChangeData.isDelete_ = false;
    albumChangeDatas.emplace(initHiddenAlbumInfo.albumId_, albumChangeData);
    return true;
}

bool CheckInsertAlbumInfos(const AssetAccurateRefresh &assetRefresh, const vector<AlbumChangeInfo> &initAlbumInfos,
    const PhotoAssetChangeInfo &queryAssetInfo, map<int32_t, AlbumChangeData> &albumChangeDatas)
{
    auto albumRefershExePtr = assetRefresh.albumRefreshExe_;
    // ˢ�����ID
    auto forceRefreshAlbums = albumRefershExePtr->forceRefreshAlbums_;
    EXPECT_TRUE(forceRefreshAlbums.empty());
    auto forceRefreshHiddenAlbums = albumRefershExePtr->forceRefreshHiddenAlbums_;
    EXPECT_TRUE(forceRefreshHiddenAlbums.empty());

    // ˢ����Ϣ�����ݿ���Ϣ
    auto refreshAlbumsMap = albumRefershExePtr->refreshAlbums_;
    for (auto &albumInfo : initAlbumInfos) {
        auto albumId = albumInfo.albumId_;
        if (refreshAlbumsMap.find(albumId) == refreshAlbumsMap.end()) {
            MEDIA_ERR_LOG("no album id, albumId:%{public}d", albumId);
            return false;
        }
        auto albumInfoIter = refreshAlbumsMap.find(albumId);
        if (albumInfoIter == refreshAlbumsMap.end()) {
            MEDIA_ERR_LOG("no album info, albumId:%{public}d", albumId);
            return false;
        }
        // ���������㷽ʽ��ͬ
        if (albumId == HIDDEN_ALBUM_ID) {
            if (!CheckInsertHiddenAlbum(albumInfoIter->second, albumInfo, queryAssetInfo, albumChangeDatas)) {
                MEDIA_ERR_LOG("hidden album info wrong, albumId:%{public}d", albumId);
                return false;
            }
            continue;
        }
        if (!CheckInsertAlbumInfo(albumInfoIter->second, albumInfo, queryAssetInfo, albumChangeDatas)) {
            MEDIA_ERR_LOG("album info wrong, albumId:%{public}d", albumId);
            return false;
        }
        ACCURATE_DEBUG("refrehInfo: %{public}s", albumInfoIter->second.ToString().c_str());
    }
    ACCURATE_DEBUG("return true");
    return true;
}

bool CheckAlbumChangeDatas(const AlbumChangeData &notifyChangeData, const AlbumChangeData &expectedChangeData)
{
    return CheckAlbumChangeData(notifyChangeData, expectedChangeData.operation_, expectedChangeData.infoBeforeChange_,
        expectedChangeData.infoAfterChange_, expectedChangeData.isDelete_);
}

bool CheckInsertAssetNotifyInfo(pair<Notification::AssetRefreshOperation, vector<PhotoAssetChangeData>> notifyInfos,
    const PhotoAssetChangeData &assetChangeData, Notification::AssetRefreshOperation operation)
{
    auto assetOperation = notifyInfos.first;
    if (assetOperation != operation) {
        MEDIA_ERR_LOG("notify asset operation wrong: %{public}d", assetOperation);
        return false;
    }
    auto photoAssetChangeDataVec = notifyInfos.second;
    if (photoAssetChangeDataVec.size() != 1) {
        MEDIA_ERR_LOG("notify asset change info size wrong: %{public}zu", photoAssetChangeDataVec.size());
        return false;
    }
    if (!CheckAssetChangeData(photoAssetChangeDataVec[0], assetChangeData)) {
        MEDIA_ERR_LOG("asset change data wrong.");
        return false;
    }
    return true;
}

bool CheckInsertNotifyAlbumInfos(map<Notification::AlbumRefreshOperation, vector<AlbumChangeData>> notifyAlbumInfos,
    Notification::AlbumRefreshOperation operation, const map<int32_t, AlbumChangeData> albumChangeDatas,
    int64_t notifySize)
{
    auto iter = notifyAlbumInfos.find(operation);
    if (iter == notifyAlbumInfos.end()) {
        MEDIA_ERR_LOG("notify album operation wrong: %{public}d", operation);
        return false;
    }
    
    auto albumChangeDataVec = iter->second;
    if (notifySize != albumChangeDataVec.size()) {
        MEDIA_ERR_LOG("notify size wrong");
        return false;
    }
    for (auto &albumChangeData : albumChangeDataVec) {
        auto albumId = albumChangeData.infoAfterChange_.albumId_;
        auto expectedAlbumChangeIter = albumChangeDatas.find(albumId);
        if (expectedAlbumChangeIter == albumChangeDatas.end()) {
            MEDIA_ERR_LOG("no albumId:%{public}d", albumId);
            return false;
        }
        if (!CheckAlbumChangeDatas(albumChangeData, expectedAlbumChangeIter->second)) {
            MEDIA_ERR_LOG("album change data wrong: %{public}d", albumId);
            return false;
        }
    }
    return true;
}

bool CheckInsertNotifyInfos(const AssetAccurateRefresh &assetRefresh, const PhotoAssetChangeData &assetChangeData,
    const map<int32_t, AlbumChangeData> albumChangeDatas)
{
    auto notifyAssetInfos = assetRefresh.notifyExe_->notifyInfos_;
    if (notifyAssetInfos.size() != 1) {
        MEDIA_ERR_LOG("notify asset change type size wrong: %{public}zu", notifyAssetInfos.size());
        return false;
    }
    if (!CheckInsertAssetNotifyInfo(*(notifyAssetInfos.begin()), assetChangeData, Notification::ASSET_OPERATION_ADD)) {
        MEDIA_ERR_LOG("asset notify info wrong.");
        return false;
    }

    auto notifyAlbumInfos = assetRefresh.albumRefreshExe_->albumRefresh_->notifyExe_->notifyInfos_;
    if (notifyAlbumInfos.size() != 1) {
        MEDIA_ERR_LOG("notify album change type size wrong: %{public}zu", notifyAlbumInfos.size());
        return false;
    }
    if (!CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE, albumChangeDatas,
        albumChangeDatas.size())) {
        MEDIA_ERR_LOG("notify album info wrong.");
        return false;
    }

    return true;
}

bool CheckAlbumInfo(const map<int32_t, AlbumChangeInfo> &refreshAlbums_, const AlbumChangeInfo &initAlbumInfo,
    const AlbumChangeInfo &expectedAlbumInfo, RdbOperation operation, map<int32_t, AlbumChangeData> &albumChangeDatas)
{
    auto refreshIter = refreshAlbums_.find(expectedAlbumInfo.albumId_);
    if (refreshIter == refreshAlbums_.end()) {
        MEDIA_ERR_LOG("No refresh album id: %{public}d", expectedAlbumInfo.albumId_);
        return false;
    }
    if (!IsEqualAlbumInfo(expectedAlbumInfo, refreshIter->second)) {
        MEDIA_ERR_LOG("refresh album info wrong");
        return false;
    }
    AlbumChangeData albumChangeData;
    albumChangeData.infoBeforeChange_ = initAlbumInfo;
    albumChangeData.infoAfterChange_ = expectedAlbumInfo;
    albumChangeData.operation_ = operation;
    albumChangeData.isDelete_ = false;
    albumChangeDatas.emplace(expectedAlbumInfo.albumId_, albumChangeData);
    return true;
}
bool CheckAssetNotifyInfo(const map<Notification::AssetRefreshOperation, vector<PhotoAssetChangeData>> &notifyInfos,
    Notification::AssetRefreshOperation operation, const PhotoAssetChangeData &assetChangeData)
{
    auto iter = notifyInfos.find(operation);
    if (iter == notifyInfos.end()) {
        MEDIA_ERR_LOG("no operation: %{public}d", operation);
        return false;
    }
    auto assetChangeDatas = iter->second;
    for (auto assetChangeData : assetChangeDatas) {
        if (CheckAssetChangeData(assetChangeData, assetChangeData)) {
            return true;
        }
    }
    MEDIA_ERR_LOG("no equal asset change data.");
    return false;
}
void PrepareNormalAssets()
{
    vector<ValuesBucket> values;
    values.push_back(GetAssetInsertValue(GetFavoriteImageAsset()));
    values.push_back(GetAssetInsertValue(GetFavoriteVideoAsset()));
    values.push_back(GetAssetInsertValue(GetImageAsset()));
    int64_t insertNums = 0;
    auto ret = g_rdbStore->BatchInsert(insertNums, PhotoColumn::PHOTOS_TABLE, values);
    ACCURATE_DEBUG("ret: %{public}d, insert values: %{public}" PRId64, ret, insertNums);
}

void ModifyAssetDateTime(int64_t dateTaken)
{
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.NotEqualTo(PhotoColumn::MEDIA_ID, 0);
    ValuesBucket value;
    value.PutInt(PhotoColumn::MEDIA_DATE_TAKEN, dateTaken);
    value.PutInt(PhotoColumn::MEDIA_DATE_ADDED, dateTaken);
    int32_t changedRows = 0;
    auto ret = g_rdbStore->Update(changedRows, value, predicates);
    ACCURATE_DEBUG("ret: %{public}d, insert values: %{public}d", ret, changedRows);
}

void PrepareTrashAssets()
{
    vector<ValuesBucket> values;
    values.push_back(GetAssetInsertValue(GetTrashAsset()));
    int64_t insertNums = 0;
    auto ret = g_rdbStore->BatchInsert(insertNums, PhotoColumn::PHOTOS_TABLE, values);
    ACCURATE_DEBUG("ret: %{public}d, insert values: %{public}" PRId64, ret, insertNums);
}

void PrepareHiddenAssets()
{
    vector<ValuesBucket> values;
    values.push_back(GetAssetInsertValue(GetFavoriteImageHiddenAsset()));
    values.push_back(GetAssetInsertValue(GetVideoHiddenAsset()));
    values.push_back(GetAssetInsertValue(GetImageHiddenAsset()));
    int64_t insertNums = 0;
    auto ret = g_rdbStore->BatchInsert(insertNums, PhotoColumn::PHOTOS_TABLE, values);
    ACCURATE_DEBUG("ret: %{public}d, insert values: %{public}" PRId64, ret, insertNums);
}

} // namespace

void AssetAccurateRefreshTest::SetUpTestCase()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    SetTables();
}

void AssetAccurateRefreshTest::SetUp()
{
    PrepareAlbumData();
}

void AssetAccurateRefreshTest::TearDownTestCase()
{
    CleanTestTables();
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    this_thread::sleep_for(chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("Clean is finish");
}

void AssetAccurateRefreshTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
    RdbPredicates alumPredicates(PhotoAlbumColumns::TABLE);
    alumPredicates.NotEqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(0));
    
    int deleteRows = 0;
    g_rdbStore->Delete(deleteRows, alumPredicates);
    MEDIA_INFO_LOG("delete album: %{public}d", deleteRows);

    RdbPredicates photosPredicates(PhotoColumn::PHOTOS_TABLE);
    photosPredicates.GreaterThan(PhotoColumn::MEDIA_ID, to_string(0));
    g_rdbStore->Delete(deleteRows, photosPredicates);
    MEDIA_INFO_LOG("delete Photos: %{public}d", deleteRows);
    MEDIA_INFO_LOG("TearDown end");
}

HWTEST_F(AssetAccurateRefreshTest, Init_001, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    auto ret = assetRefresh.Init();
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(assetRefresh.dataManager_ != nullptr);
    EXPECT_TRUE(assetRefresh.notifyExe_ != nullptr);
}

HWTEST_F(AssetAccurateRefreshTest, Insert_002, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetFavoriteVideoAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 0);
    
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    assetChangeData.isContentChanged_ = false;
    assetChangeData.thumbnailChangeStatus_ = 0;
    assetChangeData.isDelete_ = false;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos =
        { FAVORITE_ALBUM_INFO, VIDEO_ALBUM_INFO, GetUserInsertInfo(FAVORITE_VIDEO_ASSET_ALBUM_ID)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));

    // Notify
    assetRefresh.Notify();
    EXPECT_TRUE(CheckInsertNotifyInfos(assetRefresh, assetChangeData, albumChangeDatas));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_003, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetVideoAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos = { VIDEO_ALBUM_INFO, GetUserInsertInfo(assetInfo.ownerAlbumId_)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));

    // Notify
    assetRefresh.Notify();
    EXPECT_TRUE(CheckInsertNotifyInfos(assetRefresh, assetChangeData, albumChangeDatas));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_004, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetFavoriteImageAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos =
        { FAVORITE_ALBUM_INFO, IMAGE_ALBUM_INFO, GetUserInsertInfo(assetInfo.ownerAlbumId_)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));

    // Notify
    assetRefresh.Notify();
    EXPECT_TRUE(CheckInsertNotifyInfos(assetRefresh, assetChangeData, albumChangeDatas));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_005, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetImageAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos = { IMAGE_ALBUM_INFO, GetUserInsertInfo(assetInfo.ownerAlbumId_)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));

    // Notify
    assetRefresh.Notify();
    EXPECT_TRUE(CheckInsertNotifyInfos(assetRefresh, assetChangeData, albumChangeDatas));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_006, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetFavoriteVideoHiddenAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // �ʲ����ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // �ʲ�data manager��Ϣ
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos =
        { FAVORITE_ALBUM_INFO, VIDEO_ALBUM_INFO, HIDDEN_ALBUM_INFO, GetUserInsertInfo(assetInfo.ownerAlbumId_)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));
    
    // Notify
    assetRefresh.Notify();
    // �ʲ�֪ͨ
    auto notifyAssetInfos = assetRefresh.notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAssetInfos.size() == 1);
    EXPECT_TRUE(CheckInsertAssetNotifyInfo(*(notifyAssetInfos.begin()), assetChangeData,
        Notification::ASSET_OPERATION_ADD_HIDDEN));
    
    auto notifyAlbumInfos = assetRefresh.albumRefreshExe_->albumRefresh_->notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAlbumInfos.size() == 2);
    EXPECT_TRUE(CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE_HIDDEN,
        albumChangeDatas, 1));
    EXPECT_TRUE(
        CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE, albumChangeDatas, 3));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_007, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetCloudAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos =
        { IMAGE_ALBUM_INFO, CLOUD_ENHANCEMENT_ALBUM_INFO, GetUserInsertInfo(assetInfo.ownerAlbumId_)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));
    
    // Notify
    assetRefresh.Notify();
    // �ʲ�֪ͨ
    auto notifyAssetInfos = assetRefresh.notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAssetInfos.size() == 1);
    EXPECT_TRUE(CheckInsertAssetNotifyInfo(*(notifyAssetInfos.begin()), assetChangeData,
        Notification::ASSET_OPERATION_ADD));
    
    auto notifyAlbumInfos = assetRefresh.albumRefreshExe_->albumRefresh_->notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAlbumInfos.size() == 1);
    EXPECT_TRUE(
        CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE, albumChangeDatas, 3));
}

HWTEST_F(AssetAccurateRefreshTest, Insert_008, TestSize.Level2)
{
    AssetAccurateRefresh assetRefresh;
    int64_t outRowId = 0;
    auto assetInfo = GetTrashAsset();
    auto value = GetAssetInsertValue(assetInfo);
    auto ret = assetRefresh.Insert(outRowId, PhotoColumn::PHOTOS_TABLE, value);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(outRowId > 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(assetInfo.fileId_);
    EXPECT_TRUE(CheckAssetEqual(assetInfo, queryAssetInfo));

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_ADD;
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos = { TRASH_ALBUM_INFO };
    map<int32_t, AlbumChangeData> albumChangeDatas;
    EXPECT_TRUE(CheckInsertAlbumInfos(assetRefresh, initAlbumInfos, queryAssetInfo, albumChangeDatas));
    
    // Notify
    assetRefresh.Notify();
    // �ʲ�֪ͨ
    auto notifyAssetInfos = assetRefresh.notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAssetInfos.size() == 1);
    EXPECT_TRUE(CheckInsertAssetNotifyInfo(*(notifyAssetInfos.begin()), assetChangeData,
        Notification::ASSET_OPERATION_ADD_TRASH));
    
    auto notifyAlbumInfos = assetRefresh.albumRefreshExe_->albumRefresh_->notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAlbumInfos.size() == 1);
    EXPECT_TRUE(CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE_TRASH,
        albumChangeDatas, 1));
}

// trash �Ƿ���
HWTEST_F(AssetAccurateRefreshTest, Update_009, TestSize.Level2)
{
    PrepareNormalAssets();
    // �޸�1��
    ModifyAssetDateTime(12345); // dateTakenʱ��С�����е����coverDateTime

    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::MEDIA_ID, FAVORITE_IMAGE_ASSET_FILE_ID);
    ValuesBucket value;
    int64_t dataTrashTime = 1000000;
    value.PutInt(PhotoColumn::MEDIA_DATE_TRASHED, dataTrashTime);
    AssetAccurateRefresh assetRefresh;
    int32_t changedRow = 0;
    auto ret = assetRefresh.Update(changedRow, value, predicates);
    EXPECT_TRUE(ret == ACCURATE_REFRESH_RET_OK);
    EXPECT_TRUE(changedRow == 1);
    // ���ݿ�
    auto queryAssetInfo = GetAssetInfo(FAVORITE_IMAGE_ASSET_FILE_ID);
    EXPECT_TRUE(queryAssetInfo.dateTrashedMs_ == dataTrashTime);

    // data manager
    auto dataManagerPtr = assetRefresh.dataManager_;
    auto changeDatasMap = dataManagerPtr->changeDatas_;
    PhotoAssetChangeData assetChangeData;
    assetChangeData.operation_ = RDB_OPERATION_UPDATE;
    assetChangeData.infoBeforeChange_ = GetFavoriteImageAsset();
    assetChangeData.infoAfterChange_ = queryAssetInfo;
    EXPECT_TRUE(changeDatasMap.size() == 1);
    auto iter = changeDatasMap.begin();
    EXPECT_TRUE(CheckAssetChangeData(iter->second, assetChangeData));

    // album ˢ��
    assetRefresh.RefreshAlbum();
    // ���ˢ����Ϣ�����ݿ���Ϣ��֪ͨ��Ϣ
    vector<AlbumChangeInfo> initAlbumInfos = { FAVORITE_ALBUM_INFO, IMAGE_ALBUM_INFO, TRASH_ALBUM_INFO,
        GetUserInsertInfo(FAVORITE_IMAGE_ASSET_ALBUM_ID)};
    map<int32_t, AlbumChangeData> albumChangeDatas;
    
    auto albumRefershExePtr = assetRefresh.albumRefreshExe_;
    // ˢ����Ϣ�����ݿ���Ϣ
    auto refreshAlbumsMap = albumRefershExePtr->refreshAlbums_;
    AlbumChangeInfo refreshAlbumInfo = FAVORITE_ALBUM_INFO;
    refreshAlbumInfo.count_--;
    refreshAlbumInfo.imageCount_--;
    CheckAlbumInfo(refreshAlbumsMap, FAVORITE_ALBUM_INFO, refreshAlbumInfo, RDB_OPERATION_UPDATE, albumChangeDatas);

    refreshAlbumInfo = IMAGE_ALBUM_INFO;
    refreshAlbumInfo.count_--;
    refreshAlbumInfo.imageCount_--;
    CheckAlbumInfo(refreshAlbumsMap, IMAGE_ALBUM_INFO, refreshAlbumInfo, RDB_OPERATION_UPDATE, albumChangeDatas);
    
    refreshAlbumInfo = GetUserInsertInfo(FAVORITE_IMAGE_ASSET_ALBUM_ID);
    refreshAlbumInfo.count_--;
    refreshAlbumInfo.imageCount_--;
    CheckAlbumInfo(refreshAlbumsMap, GetUserInsertInfo(FAVORITE_IMAGE_ASSET_ALBUM_ID), refreshAlbumInfo,
        RDB_OPERATION_UPDATE, albumChangeDatas);

    // trash�����·���
    refreshAlbumInfo = TRASH_ALBUM_INFO;
    refreshAlbumInfo.count_++;
    refreshAlbumInfo.imageCount_++;
    CheckAlbumInfo(refreshAlbumsMap, TRASH_ALBUM_INFO, refreshAlbumInfo, RDB_OPERATION_UPDATE, albumChangeDatas);
    
    // Notify
    assetRefresh.Notify();
    // �ʲ�֪ͨ
    auto notifyAssetInfos = assetRefresh.notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAssetInfos.size() == 2);
    CheckAssetNotifyInfo(notifyAssetInfos, Notification::ASSET_OPERATION_UPDATE_ADD_TRASH, assetChangeData);
    CheckAssetNotifyInfo(notifyAssetInfos, Notification::ASSET_OPERATION_UPDATE_REMOVE_NORMAL, assetChangeData);

    auto notifyAlbumInfos = assetRefresh.albumRefreshExe_->albumRefresh_->notifyExe_->notifyInfos_;
    EXPECT_TRUE(notifyAlbumInfos.size() == 2);
    EXPECT_TRUE(
        CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE_TRASH, albumChangeDatas, 1));
    EXPECT_TRUE(
        CheckInsertNotifyAlbumInfos(notifyAlbumInfos, Notification::ALBUM_OPERATION_UPDATE, albumChangeDatas, 3));
}

HWTEST_F(AssetAccurateRefreshTest, Update_010, TestSize.Level2)
{
    PrepareNormalAssets();
    // �޸�3��
}

// unTrash
HWTEST_F(AssetAccurateRefreshTest, Update_011, TestSize.Level2)
{
    PrepareTrashAssets();
}

// hidden
HWTEST_F(AssetAccurateRefreshTest, Update_012, TestSize.Level2)
{
    PrepareNormalAssets();
}

// unHidden
HWTEST_F(AssetAccurateRefreshTest, Update_013, TestSize.Level2)
{
    PrepareHiddenAssets();
}

// ɾ
//����վ

// ����ɾ��


// ��
// ���ղ� -> �ղ�
// �ղ� -> ���ղ�

// �ǻ���վ-> ����վ
// ����վ-> �ǻ���վ

// �ֶα仯syncStatus_��cleanFlag_��timePending_��isTemp_��burstCoverLevel_

} // namespace Media
} // namespace OHOS