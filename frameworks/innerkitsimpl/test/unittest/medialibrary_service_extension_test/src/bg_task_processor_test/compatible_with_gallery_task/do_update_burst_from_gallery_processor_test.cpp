/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "bg_task_processor_test.h"

#define private public
#include "do_update_burst_from_gallery_processor.h"
#undef private
#include "media_column.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "photo_map_column.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
struct BurstResult {
    int64_t fileId;
    string title;
    int32_t mediaType;
    int32_t subtype;
    int32_t isFavourite;
    int32_t burstCoverLevel;
    string burstKey;
    int32_t burstKeyLength;
    bool isCover;
    int32_t mapAlbum;
};

void InsertBurstAsset(BurstResult &result)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, result.mediaType);
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, result.title);
    valuesBucket.PutInt(PhotoColumn::PHOTO_SUBTYPE, result.subtype);
    valuesBucket.PutInt(MediaColumn::MEDIA_IS_FAV, result.isFavourite);
    if (result.burstKey != "") {
        valuesBucket.PutString(PhotoColumn::PHOTO_BURST_KEY, result.burstKey);
    }
    
    int32_t ret = rdbStore->Insert(result.fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
}

void InsertPhotomapForBurst(BurstResult result)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    int64_t fileId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(PhotoMap::ASSET_ID, result.fileId);
    valuesBucket.PutInt(PhotoMap::ALBUM_ID, result.mapAlbum);

    int32_t ret = rdbStore->Insert(fileId, PhotoMap::TABLE, valuesBucket);
    EXPECT_EQ(ret, E_OK);
}

void ValidBurstValue(BurstResult &exResult)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    string querySql = "SELECT p1." + MediaColumn::MEDIA_ID + ", p1." + MediaColumn::MEDIA_TITLE + ", p1." +
        PhotoColumn::PHOTO_SUBTYPE + ", p1." + MediaColumn::MEDIA_IS_FAV + ", p1." + PhotoColumn::PHOTO_BURST_KEY +
        ", p1." + PhotoColumn::PHOTO_BURST_COVER_LEVEL + ", p2." + PhotoMap::ALBUM_ID + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " AS p1 JOIN " + PhotoMap::TABLE + " AS p2 ON p1." + MediaColumn::MEDIA_ID +
        " = p2." + PhotoMap::ASSET_ID + " WHERE p1." + MediaColumn::MEDIA_ID + " = " + to_string(exResult.fileId);

    auto resultSet = rdbStore->QueryByStep(querySql);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    EXPECT_EQ(ret, E_OK);
    string titleValue = GetStringVal(MediaColumn::MEDIA_TITLE, resultSet);
    EXPECT_EQ(titleValue, exResult.title);
    int32_t subtypeValue = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    EXPECT_EQ(subtypeValue, exResult.subtype);
    int32_t isFavouriteValue = GetInt32Val(MediaColumn::MEDIA_IS_FAV, resultSet);
    EXPECT_EQ(isFavouriteValue, exResult.isFavourite);
    int32_t burstCoverLevelValue = GetInt32Val(PhotoColumn::PHOTO_BURST_COVER_LEVEL, resultSet);
    EXPECT_EQ(burstCoverLevelValue, exResult.burstCoverLevel);
    string burstKeyValue = GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet);
    EXPECT_EQ(burstKeyValue.size(), exResult.burstKeyLength);
    int32_t mapAlbumValue = GetInt32Val(PhotoMap::ALBUM_ID, resultSet);
    resultSet->Close();
    EXPECT_EQ(mapAlbumValue, exResult.mapAlbum);

    if (exResult.isCover && exResult.burstKeyLength > 0) {
        exResult.burstKey = burstKeyValue;
    }
    if (!exResult.isCover && exResult.burstKeyLength > 0) {
        EXPECT_EQ(burstKeyValue, exResult.burstKey);
    }
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, do_update_burst_from_gallery_processor_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("start do_update_burst_from_gallery_processor_test_001");
    struct BurstResult burstCover = {-1, "IMG_12345678_123456_BURST001_COVER",
        static_cast<int32_t>(MEDIA_TYPE_IMAGE), static_cast<int32_t>(PhotoSubType::DEFAULT), 0,
        static_cast<int32_t>(BurstCoverLevelType::COVER), "", 0, true, 8};
    InsertBurstAsset(burstCover);
    InsertPhotomapForBurst(burstCover);
    ValidBurstValue(burstCover);

    struct BurstResult burstMember = {-1, "IMG_12345678_123456_BURST002",
        static_cast<int32_t>(MEDIA_TYPE_IMAGE), static_cast<int32_t>(PhotoSubType::DEFAULT), 0,
        static_cast<int32_t>(BurstCoverLevelType::COVER), "", 0, false, 8};
    InsertBurstAsset(burstMember);
    InsertPhotomapForBurst(burstMember);
    ValidBurstValue(burstMember);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    auto result = processor.UpdateBurstFromGallery();
    EXPECT_EQ(result, E_OK);

    burstCover.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    burstCover.burstKeyLength = 36;
    ValidBurstValue(burstCover);

    burstMember.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    burstMember.burstCoverLevel = static_cast<int32_t>(BurstCoverLevelType::MEMBER);
    burstMember.burstKeyLength = 36;
    burstMember.burstKey = burstCover.burstKey;
    ValidBurstValue(burstMember);
    MEDIA_INFO_LOG("end do_update_burst_from_gallery_processor_test_001");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, do_update_burst_from_gallery_processor_test_002, TestSize.Level2)
{
    MEDIA_INFO_LOG("start do_update_burst_from_gallery_processor_test_002");
    struct BurstResult burstCover = {-1, "IMG_12345678_123456_BURST001_cover",
        static_cast<int32_t>(MEDIA_TYPE_IMAGE), static_cast<int32_t>(PhotoSubType::DEFAULT), 0,
        static_cast<int32_t>(BurstCoverLevelType::COVER), "", 0, true, 8};
    InsertBurstAsset(burstCover);
    InsertPhotomapForBurst(burstCover);
    ValidBurstValue(burstCover);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    auto result = processor.UpdateBurstFromGallery();
    EXPECT_EQ(result, E_OK);

    // IMG_12345678_123456_BURST001_cover is burst cover (case-insensitive to letters)
    burstCover.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    burstCover.burstKeyLength = 36;
    ValidBurstValue(burstCover);
    MEDIA_INFO_LOG("end do_update_burst_from_gallery_processor_test_002");
}

HWTEST_F(MediaLibraryBgTaskProcessorTest, do_update_burst_from_gallery_processor_test_003, TestSize.Level2)
{
    MEDIA_INFO_LOG("start do_update_burst_from_gallery_processor_test_003");
    struct BurstResult burstCover = {-1, "IMG_12345678_123456_BURST_cover",
        static_cast<int32_t>(MEDIA_TYPE_IMAGE), static_cast<int32_t>(PhotoSubType::DEFAULT), 0,
        static_cast<int32_t>(BurstCoverLevelType::COVER), "", 0, true, 8};
    InsertBurstAsset(burstCover);
    InsertPhotomapForBurst(burstCover);
    ValidBurstValue(burstCover);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    auto result = processor.UpdateBurstFromGallery();
    EXPECT_EQ(result, E_OK);

    // IMG_12345678_123456_BURST_cover is not burst cover (case-insensitive to letters)
    ValidBurstValue(burstCover);
    MEDIA_INFO_LOG("end do_update_burst_from_gallery_processor_test_003");
}

} // namespace Media
} // namespace OHOS
