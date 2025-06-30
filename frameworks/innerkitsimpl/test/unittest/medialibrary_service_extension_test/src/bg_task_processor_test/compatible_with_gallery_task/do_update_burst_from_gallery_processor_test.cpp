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
#include "userfile_manager_types.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t INSERT_1_DATA = 1;
static constexpr int32_t INSERT_201_DATA = 201;

static constexpr int32_t QUERY_0_DATA = 0;
static constexpr int32_t QUERY_1_DATA = 1;
static constexpr int32_t QUERY_201_DATA = 201;

static std::string COVER_TITLE_TYPE1 = "IMG_12345678_123456_BURST001_COVER";
static std::string COVER_TITLE_MEMBER1 = "IMG_12345678_123456_BURST002";

static std::string COVER_TITLE_TYPE2 = "IMG_12345678_123456_1_BURST001_COVER";
static std::string COVER_TITLE_MEMBER2 = "IMG_12345678_123456_1_BURST002";

static std::string TEST_BURST_KEY = "XXXXXXXX_XXXX_XXXXXXXX_XXXX_XXXXXXXX";
static constexpr int32_t BURST_KEY_COUNT = 36;

static constexpr int32_t OWNER_ALBUM_ID_50 = 50;
static constexpr int32_t OWNER_ALBUM_ID_51 = 51;

struct BurstResult {
    int64_t fileId;
    string title;
    MediaType mediaType;
    PhotoSubType subtype;
    int32_t isFavourite;
    BurstCoverLevelType burstCoverLevel;
    string burstKey;
    int32_t burstKeyLength;
    bool isCover;
    int32_t ownerAlbumId;
};

int32_t InsertBurstAsset(BurstResult &result)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MediaColumn::MEDIA_TYPE, static_cast<int32_t>(result.mediaType));
    valuesBucket.PutString(MediaColumn::MEDIA_TITLE, result.title);
    valuesBucket.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(result.subtype));
    valuesBucket.PutInt(MediaColumn::MEDIA_IS_FAV, result.isFavourite);
    if (result.burstKey != "") {
        valuesBucket.PutString(PhotoColumn::PHOTO_BURST_KEY, result.burstKey);
    }
    
    int32_t ret = rdbStore->Insert(result.fileId, PhotoColumn::PHOTOS_TABLE, valuesBucket);
    return ret;
}

void ValidBurstValue(BurstResult &exResult)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    EXPECT_NE(rdbStore, nullptr);

    std::vector<std::string> columns = {
        MediaColumn::MEDIA_ID, MediaColumn::MEDIA_TITLE, PhotoColumn::PHOTO_SUBTYPE, MediaColumn::MEDIA_IS_FAV,
        PhotoColumn::PHOTO_BURST_KEY, PhotoColumn::PHOTO_BURST_COVER_LEVEL
    };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY, MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_ID, exResult.fileId);

    auto resultSet = rdbStore->Query(cmd, columns);
    EXPECT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    EXPECT_EQ(ret, E_OK);
    int32_t subtypeValue = GetInt32Val(PhotoColumn::PHOTO_SUBTYPE, resultSet);
    EXPECT_EQ(subtypeValue, static_cast<int32_t>(exResult.subtype));
    int32_t isFavouriteValue = GetInt32Val(MediaColumn::MEDIA_IS_FAV, resultSet);
    EXPECT_EQ(isFavouriteValue, exResult.isFavourite);
    int32_t burstCoverLevelValue = GetInt32Val(PhotoColumn::PHOTO_BURST_COVER_LEVEL, resultSet);
    EXPECT_EQ(burstCoverLevelValue, static_cast<int32_t>(exResult.burstCoverLevel));
    string burstKeyValue = GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet);
    EXPECT_EQ(burstKeyValue.size(), exResult.burstKeyLength);
    resultSet->Close();

    if (exResult.isCover && exResult.burstKeyLength > 0) {
        exResult.burstKey = burstKeyValue;
    }
    if (!exResult.isCover && exResult.burstKeyLength > 0) {
        EXPECT_EQ(burstKeyValue, exResult.burstKey);
    }
}

int32_t InsertWrongCoverLevelAsset(int32_t count, int64_t &outRowId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return E_ERR;
    }

    NativeRdb::ValuesBucket value;
    value.Put(PhotoColumn::PHOTO_BURST_COVER_LEVEL, 0);
    std::vector<NativeRdb::ValuesBucket> insertValues;
    for (int i = 0; i < count; ++i) {
        insertValues.push_back(value);
    }
    int32_t ret = rdbStore->BatchInsert(outRowId, PhotoColumn::PHOTOS_TABLE, insertValues);
    return ret;
}

int32_t QueryWrongCoverLevelAssetCount(int32_t &count, int32_t burstCoverLevel)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return E_ERR;
    }

    vector<string> columns = { MediaColumn::MEDIA_ID };
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY, MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL, burstCoverLevel);

    auto resultSet = rdbStore->Query(cmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_ERR;
    }
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("failed to GetRowCount");
        return E_ERR;
    }
    resultSet->Close();
    return E_OK;
}

/**
 * @tc.name: UpdateBurstCoverLevelFromGallery_test_001
 * @tc.desc: 数据库中没有需要更新的数据时, 会及时返回
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstCoverLevelFromGallery_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_001 start");
    auto processor = DoUpdateBurstFromGalleryProcessor();
    auto ret = processor.UpdateBurstCoverLevelFromGallery();
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryWrongCoverLevelAssetCount(count, static_cast<int32_t>(BurstCoverLevelType::COVER));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_0_DATA);
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_001 end");
}

/**
 * @tc.name: UpdateBurstCoverLevelFromGallery_test_002
 * @tc.desc: burst_cover_level = 0 时, 会更新为默认值 1
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstCoverLevelFromGallery_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_002 start");
    int64_t outRow = -1;
    int32_t ret = InsertWrongCoverLevelAsset(INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.UpdateBurstCoverLevelFromGallery();
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryWrongCoverLevelAssetCount(count, static_cast<int32_t>(BurstCoverLevelType::COVER));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_1_DATA);
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_002 end");
}

/**
 * @tc.name: UpdateBurstCoverLevelFromGallery_test_003
 * @tc.desc: burst_cover_level = 0 对应的数据超过200条时, 会批量循坏更新
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstCoverLevelFromGallery_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_003 start");
    int64_t outRow = -1;
    int32_t ret = InsertWrongCoverLevelAsset(INSERT_201_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_201_DATA);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.UpdateBurstCoverLevelFromGallery();
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryWrongCoverLevelAssetCount(count, static_cast<int32_t>(BurstCoverLevelType::COVER));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_201_DATA);
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_003 end");
}

/**
 * @tc.name: UpdateBurstCoverLevelFromGallery_test_004
 * @tc.desc: 后台任务停止时, 会在 UpdateBurstCoverLevelFromGallery 中停止
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstCoverLevelFromGallery_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_004 start");
    int64_t outRow = -1;
    int32_t ret = InsertWrongCoverLevelAsset(INSERT_1_DATA, outRow);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(outRow, INSERT_1_DATA);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.Stop("");
    EXPECT_EQ(ret, E_OK);
    ret = processor.UpdateBurstCoverLevelFromGallery();
    EXPECT_EQ(ret, E_OK);

    int32_t count = -1;
    ret = QueryWrongCoverLevelAssetCount(count, static_cast<int32_t>(BurstCoverLevelType::COVER));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_0_DATA);

    count = -1;
    ret = QueryWrongCoverLevelAssetCount(count, 0);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, QUERY_1_DATA);
    MEDIA_INFO_LOG("UpdateBurstCoverLevelFromGallery_test_004 end");
}

/**
 * @tc.name: UpdateBurstFromGallery_test_001
 * @tc.desc: 命名为 IMG_XXXXXXXX_XXXXXX_BURSTXXX_COVER 的封面, 会被转变为连拍照片
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstFromGallery_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_001 start");
    BurstResult burstCover = { -1, COVER_TITLE_TYPE1, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::DEFAULT, 0, BurstCoverLevelType::COVER, "", 0, true, OWNER_ALBUM_ID_50 };
    auto ret = InsertBurstAsset(burstCover);
    EXPECT_EQ(ret, E_OK);

    BurstResult burstMember = {-1, COVER_TITLE_MEMBER1, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::DEFAULT, 0, BurstCoverLevelType::MEMBER, "", 0, true, OWNER_ALBUM_ID_50 };
    ret = InsertBurstAsset(burstMember);
    EXPECT_EQ(ret, E_OK);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.UpdateBurstFromGallery();
    EXPECT_EQ(ret, E_OK);

    burstCover.subtype = PhotoSubType::BURST;
    burstCover.burstKeyLength = 36;
    ValidBurstValue(burstCover);

    burstMember.subtype = PhotoSubType::BURST;
    burstMember.burstKeyLength = 36;
    burstMember.burstKey = burstCover.burstKey;
    ValidBurstValue(burstMember);
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_001 end");
}

/**
 * @tc.name: UpdateBurstFromGallery_test_002
 * @tc.desc: 命名为 IMG_XXXXXXXX_XXXXXX_X_BURSTXXX_COVER 的封面, 会被转变为连拍照片
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstFromGallery_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_002 start");
    BurstResult burstCover = { -1, COVER_TITLE_TYPE2, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::DEFAULT, 0, BurstCoverLevelType::COVER, "", 0, true, OWNER_ALBUM_ID_50 };
    auto ret = InsertBurstAsset(burstCover);
    EXPECT_EQ(ret, E_OK);

    BurstResult burstMember = {-1, COVER_TITLE_MEMBER2, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::DEFAULT, 0, BurstCoverLevelType::MEMBER, "", 0, true, OWNER_ALBUM_ID_50 };
    ret = InsertBurstAsset(burstMember);
    EXPECT_EQ(ret, E_OK);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.UpdateBurstFromGallery();
    EXPECT_EQ(ret, E_OK);

    burstCover.subtype = PhotoSubType::BURST;
    burstCover.burstKeyLength = 36;
    ValidBurstValue(burstCover);

    burstMember.subtype = PhotoSubType::BURST;
    burstMember.burstKeyLength = 36;
    burstMember.burstKey = burstCover.burstKey;
    ValidBurstValue(burstMember);
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_002 end");
}

/**
 * @tc.name: UpdateBurstFromGallery_test_003
 * @tc.desc: 命名为 IMG_XXXXXXXX_XXXXXX_BURSTXXX 的非封面, 如果存在对应的封面, 会被转变为连拍照片
 */
HWTEST_F(MediaLibraryBgTaskProcessorTest, UpdateBurstFromGallery_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_003 start");
    BurstResult burstCover = { -1, COVER_TITLE_TYPE1, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::BURST, 0, BurstCoverLevelType::COVER, TEST_BURST_KEY, BURST_KEY_COUNT, true, OWNER_ALBUM_ID_50 };
    auto ret = InsertBurstAsset(burstCover);
    EXPECT_EQ(ret, E_OK);

    BurstResult burstMember = {-1, COVER_TITLE_MEMBER1, MediaType::MEDIA_TYPE_IMAGE,
        PhotoSubType::DEFAULT, 0, BurstCoverLevelType::MEMBER, "", 0, true, OWNER_ALBUM_ID_50 };
    ret = InsertBurstAsset(burstMember);
    EXPECT_EQ(ret, E_OK);

    auto processor = DoUpdateBurstFromGalleryProcessor();
    ret = processor.UpdateBurstFromGallery();
    EXPECT_EQ(ret, E_OK);

    burstMember.subtype = PhotoSubType::BURST;
    burstMember.burstKeyLength = 36;
    burstMember.burstKey = TEST_BURST_KEY;
    ValidBurstValue(burstMember);
    MEDIA_INFO_LOG("UpdateBurstFromGallery_test_003 end");
}

} // namespace Media
} // namespace OHOS
