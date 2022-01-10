/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "mediathumbnail_test.h"
#include "mediathumbnail_test_cb.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_ability.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
MediaLibraryDataAbility g_rdbStoreTest;
MediaLibraryThumbnail g_mediaThumbnail;
int g_index = 0;
const std::string DATABASE_NAME = MEDIA_DATA_ABILITY_DB_NAME;
std::shared_ptr<RdbStore> store = nullptr;

int MediaThumbnailTestCB::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_MEDIA_TABLE);
}

int MediaThumbnailTestCB::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void MediaThumbnailTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);

    RdbStoreConfig config(DATABASE_NAME);
    MediaThumbnailTestCB callback;
    store = RdbHelper::GetRdbStore(config, 1, callback, errCode);
    EXPECT_NE(store, nullptr);
    g_rdbStoreTest.InitMediaLibraryRdbStore();
}

void MediaThumbnailTest::TearDownTestCase(void) { }

void MediaThumbnailTest::SetUp(void) { }

void MediaThumbnailTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_001, TestSize.Level0)
{
    std::shared_ptr<RdbStore> &mstore = store;

    int64_t id = 1;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_FILE_PATH, std::string("/data/media/Pictures/Receiver_buffer7.jpg"));
    int ret = mstore->Insert(id, MEDIALIBRARY_TABLE, values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ThumbRdbOpt opts = {
        .store = mstore,
        .table = MEDIALIBRARY_TABLE,
        .row = "1",
    };

    std::string key;
    bool res = g_mediaThumbnail.CreateThumbnail(opts, key);

    EXPECT_NE(res, false);
    EXPECT_NE(key.empty(), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_002, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri);
    NativeRdb::ValuesBucket valuesBucket;
    string relativePath = "";
    string displayName = "test.jpg";

    MediaType mediaType = MEDIA_TYPE_IMAGE;

    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, std::string("/data/media/Pictures/Receiver_buffer7.jpg"));
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);

    g_index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket);
    EXPECT_NE((g_index <= 0), true);
    Uri closeUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    valuesBucket.Clear();
    valuesBucket.PutString(MEDIA_DATA_DB_URI, "/" + to_string(g_index));
    int res = g_rdbStoreTest.Insert(closeUri, valuesBucket);
    EXPECT_NE((res < 0), true);
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_003, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Size size = {
        .width = 56, .height = 56
    };

    Uri queryUri1(abilityUri  + "/" + to_string(g_index) + "?" +
        MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" +
        MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height));

    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
    };

    auto g_resultSet = g_rdbStoreTest.Query(queryUri1, columns, predicates);
    if (g_resultSet != nullptr) {
        string id;
        string thumbnailKey;
        string lcdKey;
        g_resultSet->GoToFirstRow();
        int rowCount = 0;
        g_resultSet->GetRowCount(rowCount);
        EXPECT_EQ(1, rowCount);
        int ret = g_resultSet->GetString(0, id);
        ret = g_resultSet->GetString(1, thumbnailKey);
        ret = g_resultSet->GetString(2, lcdKey);
        EXPECT_EQ(to_string(g_index), id);
        EXPECT_NE(thumbnailKey.empty(), true);
        EXPECT_NE(lcdKey.empty(), false);

        bool fromLcd = g_mediaThumbnail.isThumbnailFromLcd(size);
        auto pixelmap = g_mediaThumbnail.GetThumbnail(fromLcd?lcdKey:thumbnailKey, size);
        EXPECT_NE(pixelmap, nullptr);
        if (pixelmap != nullptr) {
            EXPECT_EQ(pixelmap->GetWidth(), size.width);
        }
    }
}

HWTEST_F(MediaThumbnailTest, MediaThumbnailTest_004, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Size size = {
        .width = 300, .height = 300
    };

    Uri queryUri(abilityUri  + "/" + to_string(g_index) + "?" +
        MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" +
        MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height));

    NativeRdb::DataAbilityPredicates predicates;
    std::vector<std::string> columns = {
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_THUMBNAIL,
        MEDIA_DATA_DB_LCD,
    };

    auto g_resultSet = g_rdbStoreTest.Query(queryUri, columns, predicates);
    if (g_resultSet != nullptr) {
        string id;
        string thumbnailKey;
        string lcdKey;
        g_resultSet->GoToFirstRow();
        int rowCount = 0;
        g_resultSet->GetRowCount(rowCount);
        EXPECT_EQ(1, rowCount);
        int ret = g_resultSet->GetString(0, id);
        ret = g_resultSet->GetString(1, thumbnailKey);
        ret = g_resultSet->GetString(2, lcdKey);
        EXPECT_EQ(to_string(g_index), id);
        EXPECT_NE(thumbnailKey.empty(), true);
        EXPECT_NE(lcdKey.empty(), true);

        bool fromLcd = g_mediaThumbnail.isThumbnailFromLcd(size);
        auto pixelmap = g_mediaThumbnail.GetThumbnail(fromLcd?lcdKey:thumbnailKey, size);

        EXPECT_NE(pixelmap, nullptr);
        if (pixelmap != nullptr) {
            EXPECT_EQ(pixelmap->GetWidth(), size.width);
        }
    }
}
}
}